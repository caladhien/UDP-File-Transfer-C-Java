#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Cross-platform socket setup: Winsock on Windows, BSD sockets on Unix.
#ifdef _WIN32
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #ifdef _MSC_VER
    #pragma comment(lib, "Ws2_32.lib")
    #endif

    typedef SOCKET socket_t;
    #define socket_close closesocket

    static void rate_limit_send(unsigned int delay_ms) {
        if (delay_ms > 0u) {
            Sleep(delay_ms);
        }
    }
    static double now_seconds(void) {
        return (double)GetTickCount() / 1000.0;
    }
#else
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <unistd.h>

    typedef int socket_t;
    #define socket_close close

    static void rate_limit_send(unsigned int delay_ms) {
        if (delay_ms > 0u) {
            usleep((useconds_t)delay_ms * 1000u);
        }
    }
    static double now_seconds(void) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
    }
#endif

// ---- Protocol constants ----
// 1400-byte payload keeps a data packet under the typical 1500 MTU (IP+UDP
// headers ~28 bytes), so routers don't fragment it.
#define MAX_DATA_PAYLOAD 1400u
#define MIN_INIT_FILENAME 1u
#define MAX_INIT_FILENAME 2048u
#define MD5_DIGEST_LEN 16u

// ---- Control channel (receiver -> sender) ----
#define CTRL_NAK 0u        // "resend these data seqs, then resend the final packet"
#define CTRL_COMPLETE 1u   // "all data received and MD5 verified, you may stop"
#define CTRL_ACK 2u        // cumulative ACK: receiver has everything below ack_base

// ---- Sliding window (fast path, used only if the receiver sends ACKs) ----
#define WINDOW_SIZE 64u            // max data packets in flight (unacked)
#define RTO_MS 100                 // retransmit timeout for an unacked packet (ms)
#define WIN_RECV_TIMEOUT_MS 20     // how long we block for an ACK each loop turn
#define PROBE_TRIES 5              // init re-sends while probing for ACK support
#define PROBE_WAIT_MS 150          // wait per probe attempt for the first ACK
#define WIN_STALL_ABORT_SEC 30.0   // give up if the window makes no progress this long

// One NAK lists at most this many missing seqs, sized to stay MTU-safe
// (5 + 4*350 = 1405 bytes, same budget as a data packet).
#define MAX_NAK_SEQS (MAX_DATA_PAYLOAD / 4u)

#define CTRL_RECV_TIMEOUT_MS 500   // wait for a control packet before nudging the receiver
#define MAX_RETRIES 10u            // consecutive idle timeouts before giving up (~5s)

// ---- Wire format ----
// There is no "type" field: a packet's role IS its sequence number.
//   seq == 0          -> init   (filename + how many data packets follow)
//   seq 1..max_seq    -> data   (one file chunk)
//   seq == max_seq+1  -> final  (MD5 of the whole file)
// #pragma pack(1) removes struct padding so these map byte-for-byte onto the
// wire. That, plus big-endian fields, is what lets the C and Java ends talk.
#pragma pack(push, 1)

typedef struct {
    uint16_t trans_id;  // unique ID for this transfer session
    uint32_t seq;       // 0 = init packet
    uint32_t max_seq;   // sequence number of the last data packet
} InitHeader;

typedef struct {
    uint16_t trans_id;
    uint32_t seq;       // 1 .. max_seq
} DataHeader;

typedef struct {
    uint16_t trans_id;
    uint32_t seq;       // max_seq + 1
    unsigned char md5[16];  // MD5 of the complete file
} FinalPacket;

// Control reply (receiver -> sender). When type == CTRL_NAK, `count`
// big-endian uint32_t missing seqs follow this header.
typedef struct {
    uint16_t trans_id;
    uint8_t  type;      // CTRL_NAK / CTRL_COMPLETE / CTRL_ACK
    uint16_t count;     // number of missing seqs that follow (NAK only)
} ControlHeader;

#pragma pack(pop)

// ---- MD5 (self-contained, no external deps; standard RFC 1321) ----
// Used to checksum the file so the receiver can verify it arrived intact.
typedef struct {
    uint32_t state[4];
    uint64_t bit_count;
    unsigned char buffer[64];
} MD5_CTX;

static uint32_t md5_left_rotate(uint32_t value, uint32_t count) {
    return (value << count) | (value >> (32u - count));
}

// Process one 64-byte block and update the state.
static void md5_transform(uint32_t state[4], const unsigned char block[64]) {
    // Start with current state values
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    
    // Decode the block into sixteen 32-bit little-endian words.
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) {
        x[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

    // Four auxiliary functions, one per round; STEP runs a single MD5 step.
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define STEP(func, a, b, c, d, xk, s, ti) \
    do { \
        (a) += func((b), (c), (d)) + (xk) + (uint32_t)(ti); \
        (a) = md5_left_rotate((a), (s)); \
        (a) += (b); \
    } while (0)

    STEP(F, a, b, c, d, x[0], 7, 0xd76aa478);
    STEP(F, d, a, b, c, x[1], 12, 0xe8c7b756);
    STEP(F, c, d, a, b, x[2], 17, 0x242070db);
    STEP(F, b, c, d, a, x[3], 22, 0xc1bdceee);
    STEP(F, a, b, c, d, x[4], 7, 0xf57c0faf);
    STEP(F, d, a, b, c, x[5], 12, 0x4787c62a);
    STEP(F, c, d, a, b, x[6], 17, 0xa8304613);
    STEP(F, b, c, d, a, x[7], 22, 0xfd469501);
    STEP(F, a, b, c, d, x[8], 7, 0x698098d8);
    STEP(F, d, a, b, c, x[9], 12, 0x8b44f7af);
    STEP(F, c, d, a, b, x[10], 17, 0xffff5bb1);
    STEP(F, b, c, d, a, x[11], 22, 0x895cd7be);
    STEP(F, a, b, c, d, x[12], 7, 0x6b901122);
    STEP(F, d, a, b, c, x[13], 12, 0xfd987193);
    STEP(F, c, d, a, b, x[14], 17, 0xa679438e);
    STEP(F, b, c, d, a, x[15], 22, 0x49b40821);

    STEP(G, a, b, c, d, x[1], 5, 0xf61e2562);
    STEP(G, d, a, b, c, x[6], 9, 0xc040b340);
    STEP(G, c, d, a, b, x[11], 14, 0x265e5a51);
    STEP(G, b, c, d, a, x[0], 20, 0xe9b6c7aa);
    STEP(G, a, b, c, d, x[5], 5, 0xd62f105d);
    STEP(G, d, a, b, c, x[10], 9, 0x02441453);
    STEP(G, c, d, a, b, x[15], 14, 0xd8a1e681);
    STEP(G, b, c, d, a, x[4], 20, 0xe7d3fbc8);
    STEP(G, a, b, c, d, x[9], 5, 0x21e1cde6);
    STEP(G, d, a, b, c, x[14], 9, 0xc33707d6);
    STEP(G, c, d, a, b, x[3], 14, 0xf4d50d87);
    STEP(G, b, c, d, a, x[8], 20, 0x455a14ed);
    STEP(G, a, b, c, d, x[13], 5, 0xa9e3e905);
    STEP(G, d, a, b, c, x[2], 9, 0xfcefa3f8);
    STEP(G, c, d, a, b, x[7], 14, 0x676f02d9);
    STEP(G, b, c, d, a, x[12], 20, 0x8d2a4c8a);

    STEP(H, a, b, c, d, x[5], 4, 0xfffa3942);
    STEP(H, d, a, b, c, x[8], 11, 0x8771f681);
    STEP(H, c, d, a, b, x[11], 16, 0x6d9d6122);
    STEP(H, b, c, d, a, x[14], 23, 0xfde5380c);
    STEP(H, a, b, c, d, x[1], 4, 0xa4beea44);
    STEP(H, d, a, b, c, x[4], 11, 0x4bdecfa9);
    STEP(H, c, d, a, b, x[7], 16, 0xf6bb4b60);
    STEP(H, b, c, d, a, x[10], 23, 0xbebfbc70);
    STEP(H, a, b, c, d, x[13], 4, 0x289b7ec6);
    STEP(H, d, a, b, c, x[0], 11, 0xeaa127fa);
    STEP(H, c, d, a, b, x[3], 16, 0xd4ef3085);
    STEP(H, b, c, d, a, x[6], 23, 0x04881d05);
    STEP(H, a, b, c, d, x[9], 4, 0xd9d4d039);
    STEP(H, d, a, b, c, x[12], 11, 0xe6db99e5);
    STEP(H, c, d, a, b, x[15], 16, 0x1fa27cf8);
    STEP(H, b, c, d, a, x[2], 23, 0xc4ac5665);

    STEP(I, a, b, c, d, x[0], 6, 0xf4292244);
    STEP(I, d, a, b, c, x[7], 10, 0x432aff97);
    STEP(I, c, d, a, b, x[14], 15, 0xab9423a7);
    STEP(I, b, c, d, a, x[5], 21, 0xfc93a039);
    STEP(I, a, b, c, d, x[12], 6, 0x655b59c3);
    STEP(I, d, a, b, c, x[3], 10, 0x8f0ccc92);
    STEP(I, c, d, a, b, x[10], 15, 0xffeff47d);
    STEP(I, b, c, d, a, x[1], 21, 0x85845dd1);
    STEP(I, a, b, c, d, x[8], 6, 0x6fa87e4f);
    STEP(I, d, a, b, c, x[15], 10, 0xfe2ce6e0);
    STEP(I, c, d, a, b, x[6], 15, 0xa3014314);
    STEP(I, b, c, d, a, x[13], 21, 0x4e0811a1);
    STEP(I, a, b, c, d, x[4], 6, 0xf7537e82);
    STEP(I, d, a, b, c, x[11], 10, 0xbd3af235);
    STEP(I, c, d, a, b, x[2], 15, 0x2ad7d2bb);
    STEP(I, b, c, d, a, x[9], 21, 0xeb86d391);

#undef F
#undef G
#undef H
#undef I
#undef STEP

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

static void md5_init(MD5_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->bit_count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

// Feed more data into the hash; called once per chunk as we read the file.
static void md5_update(MD5_CTX *ctx, const unsigned char *input, size_t len) {
    size_t index = (size_t)((ctx->bit_count / 8u) % 64u);
    ctx->bit_count += (uint64_t)len * 8u;

    size_t part_len = 64u - index;
    size_t i = 0;

    // Process every complete 64-byte block; stash the remainder for next time.
    if (len >= part_len) {
        memcpy(&ctx->buffer[index], input, part_len);
        md5_transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63u < len; i += 64u) {
            md5_transform(ctx->state, &input[i]);
        }
        index = 0;
    }
    if (i < len) {
        memcpy(&ctx->buffer[index], &input[i], len - i);
    }
}

// Pad the message, append the bit length, and emit the 16-byte digest.
static void md5_final(MD5_CTX *ctx, unsigned char digest[16]) {
    static const unsigned char padding[64] = {0x80};

    unsigned char length_bytes[8];
    for (int i = 0; i < 8; ++i) {
        length_bytes[i] = (unsigned char)((ctx->bit_count >> (8u * i)) & 0xffu);
    }

    // Pad so the length lands at the end of a block (len mod 64 == 56).
    size_t index = (size_t)((ctx->bit_count / 8u) % 64u);
    size_t pad_len = (index < 56u) ? (56u - index) : (120u - index);
    md5_update(ctx, padding, pad_len);
    md5_update(ctx, length_bytes, 8u);

    for (int i = 0; i < 4; ++i) {
        digest[i * 4] = (unsigned char)(ctx->state[i] & 0xffu);
        digest[i * 4 + 1] = (unsigned char)((ctx->state[i] >> 8u) & 0xffu);
        digest[i * 4 + 2] = (unsigned char)((ctx->state[i] >> 16u) & 0xffu);
        digest[i * 4 + 3] = (unsigned char)((ctx->state[i] >> 24u) & 0xffu);
    }
}

static void print_md5_hex(const unsigned char digest[16]) {
    for (int i = 0; i < 16; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

// Return just the filename from a path (handles both / and \ separators).
static const char *basename_from_path(const char *path) {
    const char *base = strrchr(path, '/');
    const char *alt = strrchr(path, '\\');
    if (!base || (alt && alt > base)) {
        base = alt;
    }
    return base ? base + 1 : path;
}

// Resolve an IPv4 address or hostname (e.g. "localhost"). Returns 1 on success.
static int resolve_address(const char *text, struct in_addr *out) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4 only
    hints.ai_socktype = SOCK_DGRAM;  // UDP

    if (getaddrinfo(text, NULL, &hints, &res) != 0 || res == NULL) {
        return 0;
    }
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 1;
}

// Send one datagram; returns 0 only if the whole packet went out.
static int send_all_packet(socket_t sock, const struct sockaddr_in *addr, const unsigned char *packet, size_t length) {
    int sent = sendto(sock, (const char *)packet, (int)length, 0, (const struct sockaddr *)addr, (int)sizeof(*addr));
    return sent == (int)length ? 0 : -1;
}

// Build and send the data packet for `seq` by reading its chunk from the file.
// Seq N lives at a fixed offset, so retransmits never need the file in memory.
// trans_id_net is already in network byte order. Returns 0 on success.
static int send_data_packet(socket_t sock, const struct sockaddr_in *addr, FILE *file,
                            uint16_t trans_id_net, uint32_t seq) {
    unsigned char file_buffer[MAX_DATA_PAYLOAD];
    unsigned char data_packet[sizeof(DataHeader) + MAX_DATA_PAYLOAD];

    long offset = (long)(seq - 1u) * (long)MAX_DATA_PAYLOAD;
    if (fseek(file, offset, SEEK_SET) != 0) {
        return -1;
    }
    size_t bytes_read = fread(file_buffer, 1u, MAX_DATA_PAYLOAD, file);
    if (bytes_read == 0u && ferror(file)) {
        return -1;
    }

    DataHeader header;
    header.trans_id = trans_id_net;
    header.seq = htonl(seq);
    memcpy(data_packet, &header, sizeof(header));
    memcpy(data_packet + sizeof(header), file_buffer, bytes_read);

    return send_all_packet(sock, addr, data_packet, sizeof(header) + bytes_read);
}

// Set the socket receive timeout (ms) so we can interleave sends with reads.
static void set_recv_timeout(socket_t sock, int ms) {
#ifdef _WIN32
    DWORD to = (DWORD)ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
#else
    struct timeval to;
    to.tv_sec = ms / 1000;
    to.tv_usec = (ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
#endif
}

// Test knob: DROP_PCT (0-100) randomly skips sending some packets on their first
// pass, to demonstrate that the ACK/NAK repair loop recovers them.
static int get_drop_pct(void) {
    const char *env = getenv("DROP_PCT");
    if (env == NULL) {
        return 0;
    }
    int v = atoi(env);
    if (v < 0) v = 0;
    if (v > 100) v = 100;
    return v;
}

// Decide which path to use. A windowing-capable receiver ACKs the init packet
// immediately, so we re-send init a few times and watch for that first ACK.
// Returns 1 -> use the sliding window, 0 -> fall back to blast + NAK repair.
static int probe_ack(socket_t sock, const struct sockaddr_in *addr, uint16_t trans_id,
                     const unsigned char *init_packet, size_t init_len) {
    set_recv_timeout(sock, PROBE_WAIT_MS);
    unsigned char buf[64];
    for (int attempt = 0; attempt < PROBE_TRIES; ++attempt) {
        struct sockaddr_in from;
#ifdef _WIN32
        int from_len = (int)sizeof(from);
#else
        socklen_t from_len = (socklen_t)sizeof(from);
#endif
        int r = recvfrom(sock, (char *)buf, (int)sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
        if (r >= 5) {
            uint16_t tr = (uint16_t)((buf[0] << 8) | buf[1]);
            if (tr == trans_id && buf[2] == (unsigned char)CTRL_ACK) {
                return 1;  // receiver speaks ACK -> use the window
            }
        } else {
            // Timed out: re-send init in case it (or the ACK) was lost.
            send_all_packet(sock, addr, init_packet, init_len);
        }
    }
    return 0;  // no ACK seen -> legacy receiver
}

// Resend one unit: a data packet, or the final packet when seq == max_seq+1.
static int resend_unit(socket_t sock, const struct sockaddr_in *addr, FILE *file,
                       uint16_t trans_id_net, uint32_t seq, uint32_t max_seq,
                       const FinalPacket *final_packet) {
    if (seq <= max_seq) {
        return send_data_packet(sock, addr, file, trans_id_net, seq);
    }
    return send_all_packet(sock, addr, (const unsigned char *)final_packet, sizeof(*final_packet));
}

// Sliding-window send (Selective Repeat). Keep up to WINDOW_SIZE packets in
// flight, slide forward on cumulative ACKs, and repair losses with fast
// retransmit (3 duplicate ACKs) plus an RTO backstop on the oldest unacked
// unit. MD5 is computed on each chunk's first send. Returns 0 on COMPLETE.
static int windowed_send(socket_t sock, const struct sockaddr_in *addr, FILE *file,
                         uint16_t trans_id, uint16_t trans_id_net, uint32_t max_seq,
                         uint64_t file_size, uint64_t *bytes_sent, double start_time) {
    printf("Mode: sliding window (receiver supports ACK), window=%u\n", (unsigned)WINDOW_SIZE);

    // Last-send timestamp per unit (1..max_seq for data, max_seq+1 for final).
    double *send_time = calloc((size_t)max_seq + 2u, sizeof(double));
    if (send_time == NULL) {
        fprintf(stderr, "windowed: out of memory for timers\n");
        return -1;
    }

    const int drop_pct = get_drop_pct();
    uint32_t dropped = 0u, retransmitted = 0u;

    MD5_CTX md5;
    md5_init(&md5);
    unsigned char chunk[MAX_DATA_PAYLOAD];
    unsigned char data_packet[sizeof(DataHeader) + MAX_DATA_PAYLOAD];
    DataHeader data_header;
    data_header.trans_id = trans_id_net;

    FinalPacket final_packet;
    unsigned char digest[MD5_DIGEST_LEN];
    int final_built = 0, final_sent = 0, complete = 0;

    uint32_t base = 1u;      // oldest unacked seq
    uint32_t next_seq = 1u;  // next new seq to send for the first time
    double progress_at = now_seconds();
    int dup_acks = 0;        // count of duplicate ACKs at the current base
    int fast_done = 0;       // already fast-retransmitted for this base?

    set_recv_timeout(sock, WIN_RECV_TIMEOUT_MS);

    while (1) {
        // Fill the window with new data packets.
        while (next_seq <= max_seq && next_seq < base + WINDOW_SIZE) {
            if (fseek(file, (long)(next_seq - 1u) * (long)MAX_DATA_PAYLOAD, SEEK_SET) != 0) {
                free(send_time);
                return -1;
            }
            size_t br = fread(chunk, 1u, MAX_DATA_PAYLOAD, file);
            if (br == 0u && ferror(file)) {
                free(send_time);
                return -1;
            }
            md5_update(&md5, chunk, br);  // hash on first send only

            data_header.seq = htonl(next_seq);
            memcpy(data_packet, &data_header, sizeof(data_header));
            memcpy(data_packet + sizeof(data_header), chunk, br);

            if (drop_pct > 0 && (rand() % 100) < drop_pct) {
                dropped++;  // simulate first-pass loss; RTO/ACK will repair it
            } else if (send_all_packet(sock, addr, data_packet, sizeof(data_header) + br) == 0) {
                *bytes_sent += (uint64_t)(sizeof(data_header) + br);
            }
            send_time[next_seq] = now_seconds();
            next_seq++;
        }

        // Once every chunk is hashed, build the final packet and send it once.
        if (next_seq > max_seq && !final_built) {
            md5_final(&md5, digest);
            final_packet.trans_id = trans_id_net;
            final_packet.seq = htonl(max_seq + 1u);
            memcpy(final_packet.md5, digest, sizeof(final_packet.md5));
            final_built = 1;
        }
        if (final_built && !final_sent) {
            if (send_all_packet(sock, addr, (const unsigned char *)&final_packet, sizeof(final_packet)) == 0) {
                *bytes_sent += (uint64_t)sizeof(final_packet);
            }
            send_time[max_seq + 1u] = now_seconds();
            final_sent = 1;
        }

        // Read a control packet (ACK / NAK / COMPLETE), if one is waiting.
        unsigned char cb[5u + 4u * MAX_NAK_SEQS];
        struct sockaddr_in cf;
#ifdef _WIN32
        int cfl = (int)sizeof(cf);
#else
        socklen_t cfl = (socklen_t)sizeof(cf);
#endif
        int r = recvfrom(sock, (char *)cb, (int)sizeof(cb), 0, (struct sockaddr *)&cf, &cfl);
        if (r >= 5) {
            uint16_t tr = (uint16_t)((cb[0] << 8) | cb[1]);
            if (tr == trans_id) {
                uint8_t type = cb[2];
                if (type == CTRL_COMPLETE) {
                    complete = 1;
                    break;
                } else if (type == CTRL_ACK && r >= 9) {
                    uint32_t ack_base = (uint32_t)cb[5] << 24 | (uint32_t)cb[6] << 16 |
                                        (uint32_t)cb[7] << 8 | (uint32_t)cb[8];
                    if (ack_base > base) {
                        base = ack_base;            // slide the window forward
                        progress_at = now_seconds();
                        dup_acks = 0;
                        fast_done = 0;
                    } else if (ack_base == base) {
                        // Duplicate ACK: receiver still stuck on `base`. After 3,
                        // fast-retransmit it once without waiting for the RTO.
                        if (++dup_acks >= 3 && !fast_done && base <= max_seq + 1u) {
                            if (resend_unit(sock, addr, file, trans_id_net, base, max_seq, &final_packet) == 0) {
                                retransmitted++;
                            }
                            send_time[base] = now_seconds();
                            fast_done = 1;
                        }
                    }
                } else if (type == CTRL_NAK) {
                    uint16_t count = (uint16_t)((cb[3] << 8) | cb[4]);
                    if ((size_t)r < 5u + 4u * (size_t)count) {
                        count = (uint16_t)((r - 5) / 4);
                    }
                    for (uint16_t i = 0; i < count; ++i) {
                        size_t b = 5u + (size_t)i * 4u;
                        uint32_t s = (uint32_t)cb[b] << 24 | (uint32_t)cb[b + 1] << 16 |
                                     (uint32_t)cb[b + 2] << 8 | (uint32_t)cb[b + 3];
                        if (s >= 1u && s <= max_seq) {
                            if (resend_unit(sock, addr, file, trans_id_net, s, max_seq, &final_packet) == 0) {
                                retransmitted++;
                            }
                            send_time[s] = now_seconds();
                        }
                    }
                    if (final_built) {
                        send_all_packet(sock, addr, (const unsigned char *)&final_packet, sizeof(final_packet));
                    }
                }
            }
        }

        // RTO backstop: resend the oldest unacked unit if it has gone too long
        // without an ACK. Covers the case where a retransmit itself was lost.
        double now = now_seconds();
        uint32_t upto = final_sent ? (max_seq + 1u) : (next_seq > 1u ? next_seq - 1u : 1u);
        if (base <= upto && send_time[base] > 0.0 && (now - send_time[base]) > (double)RTO_MS / 1000.0) {
            if (resend_unit(sock, addr, file, trans_id_net, base, max_seq, &final_packet) == 0) {
                retransmitted++;
            }
            send_time[base] = now;
            fast_done = 0;  // allow another fast retransmit if duplicates keep coming
        }

        // Give up if the window has made no forward progress for too long.
        if (now_seconds() - progress_at > WIN_STALL_ABORT_SEC) {
            fprintf(stderr, "windowed: no progress for %.0fs, aborting.\n", WIN_STALL_ABORT_SEC);
            break;
        }
    }

    free(send_time);

    double elapsed = now_seconds() - start_time;
    if (elapsed <= 0.0) elapsed = 0.001;
    if (dropped > 0u) {
        printf("Simulated loss: dropped %u data packets on first pass (DROP_PCT=%d)\n", dropped, drop_pct);
    }
    if (retransmitted > 0u) {
        printf("Retransmitted %u packet(s) (window RTO/NAK).\n", retransmitted);
    }
    if (complete) {
        printf("Receiver confirmed transfer COMPLETE (ACK/window).\n");
    } else {
        printf("Windowed transfer ended without COMPLETE.\n");
    }
    if (final_built) {
        printf("Transfer sent successfully!\nFile MD5 hash: ");
        print_md5_hex(digest);
    }
    printf("Total bytes sent (including protocol headers): %llu\n", (unsigned long long)*bytes_sent);
    printf("Elapsed time: %.3f seconds\n", elapsed);
    printf("Average throughput: %.2f bytes/sec\n", (double)file_size / elapsed);
    return complete ? 0 : -1;
}

int main(int argc, char **argv) {
    // Usage: udp_tx <dest_ip> <dest_port> <file_path> [pace_ms]
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: %s <dest_ip> <dest_port> <file_path> [pace_ms]\n", argv[0]);
        return 1;
    }

    const char *dest_ip = argv[1];
    const int dest_port = atoi(argv[2]);
    const char *file_path = argv[3];
    unsigned int pace_ms = (unsigned int)(argc == 5 ? atoi(argv[4]) : 1);  // ms between packets
    const char *filename = basename_from_path(file_path);  // send the name only, no path
    const size_t filename_len = strlen(filename);

    if (filename_len < MIN_INIT_FILENAME || filename_len > MAX_INIT_FILENAME) {
        fprintf(stderr, "Filename length must be between %u and %u bytes.\n", MIN_INIT_FILENAME, MAX_INIT_FILENAME);
        return 1;
    }

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }

    // Measure the file size, then rewind so we can stream it.
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(file);
        return 1;
    }
    long file_size_long = ftell(file);
    if (file_size_long < 0) {
        perror("ftell");
        fclose(file);
        return 1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(file);
        return 1;
    }

    // max_seq = number of data packets (seq 0 is init, seq max_seq+1 is final).
    uint64_t file_size = (uint64_t)file_size_long;
    uint32_t max_seq = (uint32_t)((file_size + MAX_DATA_PAYLOAD - 1u) / MAX_DATA_PAYLOAD);

    double start_time = now_seconds();
    uint64_t bytes_sent = 0u;

    // Hash the file as we send it, so we only read it once.
    MD5_CTX md5;
    md5_init(&md5);

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        fclose(file);
        return 1;
    }
#endif

    socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);  // IPv4 UDP
    #ifdef _WIN32
    if (sock == INVALID_SOCKET) {
    #else
    if (sock < 0) {
    #endif
        perror("socket");
    #ifdef _WIN32
        WSACleanup();
    #endif
        fclose(file);
        return 1;
    }

    // Windows: we recvfrom() control packets on this socket, so disable
    // SIO_UDP_CONNRESET. Otherwise an ICMP "port unreachable" makes recvfrom()
    // fail with WSAECONNRESET (10054) and spin instead of timing out cleanly.
#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
    BOOL new_behavior = FALSE;
    DWORD bytes_returned = 0;
    WSAIoctl(sock, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior),
             NULL, 0, &bytes_returned, NULL, NULL);
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)dest_port);
    if (!resolve_address(dest_ip, &addr.sin_addr)) {  // accepts IPs and hostnames
        fprintf(stderr, "Could not resolve destination address: %s\n", dest_ip);
        socket_close(sock);
    #ifdef _WIN32
        WSACleanup();
    #endif
        fclose(file);
        return 1;
    }

    // Random per-session ID so the receiver can tell our packets apart.
    srand((unsigned)time(NULL));
    uint16_t trans_id = (uint16_t)(rand() & 0xffffu);

    printf("File: %s (%llu bytes)\n", filename, (unsigned long long)file_size);
    printf("Transaction ID: %u\n", (unsigned)trans_id);
    printf("Data packets: %u\n", max_seq);
    printf("Packet pacing: %u ms\n", pace_ms);

    // All header fields go on the wire big-endian (htons/htonl) so a little-
    // endian x86 sender and the Java receiver agree on the bytes.
    unsigned char init_packet[10u + MAX_INIT_FILENAME];
    InitHeader init_header;
    init_header.trans_id = htons(trans_id);
    init_header.seq = htonl(0u);
    init_header.max_seq = htonl(max_seq);
    memcpy(init_packet, &init_header, sizeof(init_header));
    memcpy(init_packet + sizeof(init_header), filename, filename_len);

    if (send_all_packet(sock, &addr, init_packet, sizeof(init_header) + filename_len) != 0) {
        perror("sendto(init)");
        socket_close(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        fclose(file);
        return 1;
    }
    bytes_sent += (uint64_t)(sizeof(init_header) + filename_len);
    rate_limit_send(pace_ms);

    // Fast path: if the receiver ACKs the init packet, run the sliding window.
    // Otherwise fall through to blast + NAK repair, which also works against a
    // fire-and-forget receiver that never sends control packets.
    if (probe_ack(sock, &addr, trans_id, init_packet, sizeof(init_header) + filename_len)) {
        int wrc = windowed_send(sock, &addr, file, trans_id, init_header.trans_id,
                                max_seq, file_size, &bytes_sent, start_time);
        socket_close(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        fclose(file);
        return wrc == 0 ? 0 : 1;
    }
    printf("Mode: legacy blast + NAK repair (receiver did not advertise ACK)\n");

    unsigned char file_buffer[MAX_DATA_PAYLOAD];
    unsigned char data_packet[sizeof(DataHeader) + MAX_DATA_PAYLOAD];
    DataHeader data_header;
    data_header.trans_id = htons(trans_id);

    int drop_pct = get_drop_pct();
    uint32_t dropped_count = 0u;

    // Blast every data packet, hashing each chunk as we send it. Anything lost
    // here is repaired afterwards in the control loop via NAK retransmits.
    for (uint32_t seq = 1; seq <= max_seq; ++seq) {
        size_t bytes_read = fread(file_buffer, 1u, MAX_DATA_PAYLOAD, file);
        if (bytes_read == 0u && ferror(file)) {
            perror("fread");
            socket_close(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            fclose(file);
            return 1;
        }

        md5_update(&md5, file_buffer, bytes_read);  // hash while sending

        data_header.seq = htonl(seq);
        memcpy(data_packet, &data_header, sizeof(data_header));
        memcpy(data_packet + sizeof(data_header), file_buffer, bytes_read);

        if (drop_pct > 0 && (rand() % 100) < drop_pct) {
            dropped_count++;  // simulated loss; receiver will NAK it
        } else {
            if (send_all_packet(sock, &addr, data_packet, sizeof(data_header) + bytes_read) != 0) {
                perror("sendto(data)");
                socket_close(sock);
#ifdef _WIN32
                WSACleanup();
#endif
                fclose(file);
                return 1;
            }
            bytes_sent += (uint64_t)(sizeof(data_header) + bytes_read);
        }

        // Pace the loop so a tight blast doesn't overflow the kernel send buffer.
        rate_limit_send(pace_ms);
    }

    // Finalize the hash and send it in the final packet (seq = max_seq+1).
    unsigned char digest[MD5_DIGEST_LEN];
    md5_final(&md5, digest);

    FinalPacket final_packet;
    final_packet.trans_id = htons(trans_id);
    final_packet.seq = htonl(max_seq + 1u);
    memcpy(final_packet.md5, digest, sizeof(final_packet.md5));

    if (send_all_packet(sock, &addr, (const unsigned char *)&final_packet, sizeof(final_packet)) != 0) {
        perror("sendto(final)");
        socket_close(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        fclose(file);
        return 1;  // Failed to send final packet
    }
    bytes_sent += (uint64_t)sizeof(final_packet);
    if (dropped_count > 0u) {
        printf("Simulated loss: dropped %u of %u data packets on first pass (DROP_PCT=%d)\n",
               dropped_count, max_seq, drop_pct);
    }

    // Control loop: the receiver NAKs whatever it is still missing and we
    // retransmit until it confirms COMPLETE. If it never answers (a fire-and-
    // forget receiver), we give up after MAX_RETRIES idle timeouts and exit.
#ifdef _WIN32
    DWORD ctl_timeout = (DWORD)CTRL_RECV_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ctl_timeout, sizeof(ctl_timeout));
#else
    struct timeval ctl_timeout;
    ctl_timeout.tv_sec = CTRL_RECV_TIMEOUT_MS / 1000;
    ctl_timeout.tv_usec = (CTRL_RECV_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &ctl_timeout, sizeof(ctl_timeout));
#endif

    unsigned char ctl_buf[5u + 4u * MAX_NAK_SEQS];
    uint32_t retries_left = MAX_RETRIES;
    int complete = 0;
    uint32_t retransmitted = 0u;

    while (retries_left > 0u) {
        struct sockaddr_in ctl_from;
#ifdef _WIN32
        int ctl_from_len = (int)sizeof(ctl_from);
#else
        socklen_t ctl_from_len = (socklen_t)sizeof(ctl_from);
#endif
        int r = recvfrom(sock, (char *)ctl_buf, (int)sizeof(ctl_buf), 0,
                         (struct sockaddr *)&ctl_from, &ctl_from_len);

        if (r < 0) {
            // Timed out: nudge the receiver with the final packet, then count down.
            send_all_packet(sock, &addr, (const unsigned char *)&final_packet, sizeof(final_packet));
            retries_left--;
            continue;
        }
        if (r < 5) {
            continue;  // too short to be a control header
        }

        uint16_t ctl_trans = (uint16_t)((ctl_buf[0] << 8) | ctl_buf[1]);
        if (ctl_trans != trans_id) {
            continue;  // stale/foreign control packet
        }
        uint8_t ctl_type = ctl_buf[2];

        if (ctl_type == CTRL_COMPLETE) {
            complete = 1;
            break;
        }

        if (ctl_type == CTRL_NAK) {
            uint16_t count = (uint16_t)((ctl_buf[3] << 8) | ctl_buf[4]);
            if ((size_t)r < 5u + 4u * (size_t)count) {  // clamp to what actually fit
                count = (uint16_t)((r - 5) / 4);
            }
            for (uint16_t i = 0; i < count; ++i) {
                size_t base = 5u + (size_t)i * 4u;
                uint32_t s = (uint32_t)ctl_buf[base] << 24 | (uint32_t)ctl_buf[base + 1] << 16 |
                             (uint32_t)ctl_buf[base + 2] << 8 | (uint32_t)ctl_buf[base + 3];
                if (s >= 1u && s <= max_seq) {
                    if (send_data_packet(sock, &addr, file, init_header.trans_id, s) == 0) {
                        retransmitted++;
                    }
                }
            }
            // Resend the final packet too so the receiver can re-verify.
            send_all_packet(sock, &addr, (const unsigned char *)&final_packet, sizeof(final_packet));
            retries_left = MAX_RETRIES;  // got a live reply, refill the budget
        }
    }

    if (retransmitted > 0u) {
        printf("Retransmitted %u packet(s) in response to NAKs.\n", retransmitted);
    }

    if (complete) {
        printf("Receiver confirmed transfer COMPLETE (ACK received).\n");
    } else {
        printf("No ACK received; assuming fire-and-forget receiver and exiting.\n");
    }
    printf("Transfer sent successfully!\n");
    printf("File MD5 hash: ");
    print_md5_hex(digest);

    double elapsed_sec = now_seconds() - start_time;
    if (elapsed_sec <= 0.0) {
        elapsed_sec = 0.001;
    }
    printf("Total bytes sent (including protocol headers): %llu\n", (unsigned long long)bytes_sent);
    printf("Elapsed time: %.3f seconds\n", elapsed_sec);
    printf("Average throughput: %.2f bytes/sec\n", (double)file_size / elapsed_sec);

    socket_close(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    fclose(file);
    return 0;
}