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
    #include <direct.h>   // _mkdir
    #ifdef _MSC_VER
    #pragma comment(lib, "Ws2_32.lib")
    #endif

    typedef SOCKET socket_t;
    #define socket_close closesocket

    static double now_seconds(void) {
        return (double)GetTickCount() / 1000.0;
    }
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/stat.h>
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <unistd.h>

    typedef int socket_t;
    #define socket_close close

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
#define MAX_PACKET_SIZE 4096u       // largest datagram we'll accept
#define MD5_DIGEST_LEN 16u
#define RECEIVED_DIR "received_files"

// ---- Control channel (receiver -> sender) ----
#define CTRL_NAK 0u        // "resend these data seqs, then resend the final packet"
#define CTRL_COMPLETE 1u   // "all data received and MD5 verified, you may stop"
#define CTRL_ACK 2u        // cumulative ACK: "I have everything below ack_base"

// One NAK lists at most this many missing seqs, sized to stay MTU-safe
// (5 + 4*350 = 1405 bytes, same budget as a data packet).
#define MAX_NAK_SEQS (MAX_DATA_PAYLOAD / 4u)

// Short socket timeout so the loop wakes regularly to (re)send NAKs.
#define CTRL_RECV_TIMEOUT_MS 500

// ---- Wire format (must match the sender) ----
// No "type" field: a packet's role IS its sequence number.
//   seq == 0          -> init   (filename + how many data packets follow)
//   seq 1..max_seq    -> data   (one file chunk)
//   seq == max_seq+1  -> final  (MD5 of the whole file)
// #pragma pack(1) removes struct padding so these map byte-for-byte onto the wire.
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
    unsigned char md5[16];  // sender's MD5 of the complete file
} FinalPacket;

#pragma pack(pop)

// ---- MD5 (self-contained, no external deps; standard RFC 1321) ----
typedef struct {
    uint32_t state[4];
    uint64_t bit_count;
    unsigned char buffer[64];
} MD5_CTX;

// ---- File reassembly ----
// UDP can deliver packets out of order, so we stash each chunk at its seq
// position and reassemble in order at the end rather than appending on arrival.
typedef struct {
    unsigned char *data;
    uint32_t length;
    uint8_t present;       // 1 = received, 0 = still missing
} Chunk;

// State for one in-progress transfer.
typedef struct {
    uint16_t trans_id;
    uint32_t max_seq;
    char *filename;
    Chunk *chunks;               // indexed 1..max_seq (chunks[0] unused)
    unsigned char final_md5[16]; // MD5 from the sender, to verify against
    uint8_t have_init;
    uint8_t have_final;

    struct sockaddr_in6 sender;  // where to send control replies
    int sender_len;
    uint8_t have_sender;

    uint32_t ack_base;           // lowest still-missing seq (cumulative ACK point)
} Session;

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

// Feed more data into the hash; called once per chunk as we reassemble.
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

// Free everything a session allocated.
static void free_session(Session *session) {
    if (session->chunks != NULL) {
        for (uint32_t i = 0; i <= session->max_seq; ++i) {
            free(session->chunks[i].data);
        }
        free(session->chunks);
    }
    free(session->filename);
    memset(session, 0, sizeof(*session));
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

// Allocate the chunk array (indices 0..max_seq) on first use.
static int ensure_chunks(Session *session) {
    if (session->chunks == NULL) {
        session->chunks = calloc((size_t)session->max_seq + 1u, sizeof(Chunk));
        if (session->chunks == NULL) {
            return -1;
        }
    }
    return 0;
}

// Advance the cumulative ACK point past every contiguous chunk we now hold.
// ack_base ends up at the lowest seq we are still missing (or max_seq+1 if none).
static void advance_ack_base(Session *session) {
    if (session->chunks == NULL) {
        return;
    }
    if (session->ack_base < 1u) {
        session->ack_base = 1u;
    }
    while (session->ack_base <= session->max_seq && session->chunks[session->ack_base].present) {
        session->ack_base++;
    }
}

// Have all data chunks (1..max_seq) arrived?
static int all_chunks_present(const Session *session) {
    if (session->chunks == NULL) {
        return 0;
    }
    for (uint32_t seq = 1; seq <= session->max_seq; ++seq) {
        if (!session->chunks[seq].present) {
            return 0;
        }
    }
    return 1;
}

// Send a control packet back to the sender.
//   CTRL_COMPLETE -> empty body, tells the sender to stop.
//   CTRL_NAK      -> lists up to MAX_NAK_SEQS missing data seqs (count==0 means
//                    "I have all data, just resend the final/MD5 packet").
// Matches the ControlHeader wire format used by the sender.
static void send_control(socket_t sock, const Session *session, uint8_t type) {
    if (!session->have_sender) {
        return;  // We don't know where to reply yet
    }

    unsigned char buf[5u + 4u * MAX_NAK_SEQS];
    buf[0] = (unsigned char)((session->trans_id >> 8) & 0xffu);
    buf[1] = (unsigned char)(session->trans_id & 0xffu);
    buf[2] = type;

    uint16_t count = 0u;
    if (type == CTRL_NAK && session->chunks != NULL) {
        // List the missing data seqs, big-endian, capped to one datagram.
        for (uint32_t seq = 1; seq <= session->max_seq && count < MAX_NAK_SEQS; ++seq) {
            if (!session->chunks[seq].present) {
                size_t base = 5u + (size_t)count * 4u;
                buf[base] = (unsigned char)((seq >> 24) & 0xffu);
                buf[base + 1] = (unsigned char)((seq >> 16) & 0xffu);
                buf[base + 2] = (unsigned char)((seq >> 8) & 0xffu);
                buf[base + 3] = (unsigned char)(seq & 0xffu);
                count++;
            }
        }
    }

    buf[3] = (unsigned char)((count >> 8) & 0xffu);
    buf[4] = (unsigned char)(count & 0xffu);

    size_t len = 5u + (size_t)count * 4u;
    sendto(sock, (const char *)buf, (int)len, 0,
           (const struct sockaddr *)&session->sender, (int)session->sender_len);
}

// Send a cumulative ACK back to the sender. Wire layout:
//   trans_id(2) | type=CTRL_ACK | count(2)=0 | ack_base(4)   (9 bytes)
// The ACK both advertises "I support windowing" (sent once on the init packet)
// and tells a windowed sender how far its window may slide.
static void send_ack(socket_t sock, const Session *session) {
    if (!session->have_sender) {
        return;
    }
    unsigned char buf[9];
    buf[0] = (unsigned char)((session->trans_id >> 8) & 0xffu);
    buf[1] = (unsigned char)(session->trans_id & 0xffu);
    buf[2] = (unsigned char)CTRL_ACK;
    buf[3] = 0u;  // count high byte (no SACK blocks)
    buf[4] = 0u;  // count low byte
    buf[5] = (unsigned char)((session->ack_base >> 24) & 0xffu);
    buf[6] = (unsigned char)((session->ack_base >> 16) & 0xffu);
    buf[7] = (unsigned char)((session->ack_base >> 8) & 0xffu);
    buf[8] = (unsigned char)(session->ack_base & 0xffu);
    sendto(sock, (const char *)buf, 9, 0,
           (const struct sockaddr *)&session->sender, (int)session->sender_len);
}


// Process one incoming packet, classifying it by sequence number.
// Returns 0 normally (invalid packets are ignored), -1 on a fatal error.
static int handle_packet(Session *session, const unsigned char *data, size_t length) {
    if (length < sizeof(DataHeader)) {
        return 0;  // too short for even a header
    }

    // Header is big-endian (network byte order), so the high byte comes first.
    uint16_t trans_id = (uint16_t)((data[0] << 8) | data[1]);
    uint32_t seq = (uint32_t)data[2] << 24 | (uint32_t)data[3] << 16 | (uint32_t)data[4] << 8 | (uint32_t)data[5];

    // Init packet (seq 0): carries max_seq and the filename. Must come first.
    if (!session->have_init) {
        if (seq != 0u || length < sizeof(InitHeader)) {
            return 0;
        }
        uint32_t max_seq = (uint32_t)data[6] << 24 | (uint32_t)data[7] << 16 | (uint32_t)data[8] << 8 | (uint32_t)data[9];
        size_t filename_len = length - sizeof(InitHeader);  // filename follows the header
        if (filename_len < MIN_INIT_FILENAME || filename_len > MAX_INIT_FILENAME) {
            return 0;
        }

        char *filename = malloc(filename_len + 1u);
        if (filename == NULL) {
            return -1;
        }
        memcpy(filename, data + sizeof(InitHeader), filename_len);
        filename[filename_len] = '\0';

        session->trans_id = trans_id;
        session->max_seq = max_seq;
        session->filename = filename;
        session->have_init = 1;
        if (ensure_chunks(session) != 0) {
            return -1;
        }
        return 0;
    }

    // Once initialized, ignore anything from a different sender.
    if (trans_id != session->trans_id) {
        return 0;
    }

    // Final packet (seq max_seq+1): stash the sender's MD5 for verification.
    if (seq == session->max_seq + 1u && length == sizeof(FinalPacket)) {
        memcpy(session->final_md5, data + 6, 16u);
        session->have_final = 1;
        return 0;
    }

    // Otherwise it's a data packet; reject out-of-range or oversized seqs.
    if (seq == 0u || seq > session->max_seq) {
        return 0;
    }
    size_t payload_len = length - sizeof(DataHeader);
    if (payload_len > MAX_DATA_PAYLOAD) {
        return 0;
    }
    if (session->chunks == NULL && ensure_chunks(session) != 0) {
        return -1;
    }

    // Store the chunk at its seq position (handles out-of-order delivery and
    // ignores duplicates), to be reassembled in order once the transfer ends.
    if (!session->chunks[seq].present) {
        unsigned char *copy = malloc(payload_len);
        if (copy == NULL) {
            return -1;
        }
        memcpy(copy, data + sizeof(DataHeader), payload_len);
        session->chunks[seq].data = copy;
        session->chunks[seq].length = (uint32_t)payload_len;
        session->chunks[seq].present = 1;
    }
    return 0;
}


static void print_md5_hex(const unsigned char *digest, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

// Reassemble the received chunks, verify the MD5 against the sender's, and
// (if it matches) write the file to disk. Returns 0 on success.
static int finish_transfer(Session *session, const char *output_dir, double elapsed_sec) {
    if (!(session->have_init && session->have_final && session->chunks != NULL)) {
        fprintf(stderr, "Transfer incomplete.\n");
        return 1;
    }

    // Total up the chunks, bailing if any are missing.
    uint64_t total = 0;
    for (uint32_t seq = 1; seq <= session->max_seq; ++seq) {
        if (!session->chunks[seq].present) {
            fprintf(stderr, "Missing chunk %u\n", seq);
            return 1;
        }
        total += session->chunks[seq].length;
    }

    // We assemble the whole file in memory, so cap it at 2 GB.
    if (total > 2147483647u) {
        fprintf(stderr, "File too large to assemble in memory.\n");
        return 1;
    }
    unsigned char *file_bytes = malloc((size_t)total);
    if (file_bytes == NULL) {
        perror("malloc");
        return 1;
    }

    // Copy chunks in seq order into one buffer, hashing as we go.
    MD5_CTX md5;
    md5_init(&md5);
    size_t offset = 0;
    for (uint32_t seq = 1; seq <= session->max_seq; ++seq) {
        memcpy(file_bytes + offset, session->chunks[seq].data, session->chunks[seq].length);
        md5_update(&md5, session->chunks[seq].data, session->chunks[seq].length);
        offset += session->chunks[seq].length;
    }
    unsigned char computed[MD5_DIGEST_LEN];
    md5_final(&md5, computed);

    // The integrity check: our hash must equal the one the sender sent.
    printf("MD5 received: ");
    print_md5_hex(session->final_md5, MD5_DIGEST_LEN);
    printf("MD5 computed: ");
    print_md5_hex(computed, MD5_DIGEST_LEN);
    if (memcmp(computed, session->final_md5, MD5_DIGEST_LEN) != 0) {
        fprintf(stderr, "MD5 mismatch. Transfer corrupted.\n");
        free(file_bytes);
        return 1;
    }

    const char *base = basename_from_path(session->filename);  // name only, no path
    char safe_name[MAX_INIT_FILENAME + 1];
    strncpy(safe_name, base ? base : "received.bin", MAX_INIT_FILENAME);
    safe_name[MAX_INIT_FILENAME] = '\0';
    if (strlen(safe_name) == 0) {
        strcpy(safe_name, "received.bin");
    }

    // Build output_dir/received_files and make sure both directories exist.
    size_t dir_len = strlen(output_dir) + 1u + strlen(RECEIVED_DIR) + 1u;
    char *dir_path = malloc(dir_len);
    if (dir_path == NULL) {
        perror("malloc");
        free(file_bytes);
        return 1;
    }
    snprintf(dir_path, dir_len, "%s/%s", output_dir, RECEIVED_DIR);

    if (strcmp(output_dir, ".") != 0) {
#ifdef _WIN32
        if (_mkdir(output_dir) != 0 && errno != EEXIST) {
#else
        if (mkdir(output_dir, 0777) != 0 && errno != EEXIST) {
#endif
            perror("mkdir(output_dir)");
            free(dir_path);
            free(file_bytes);
            return 1;
        }
    }
#ifdef _WIN32
    if (_mkdir(dir_path) != 0 && errno != EEXIST) {
#else
    if (mkdir(dir_path, 0777) != 0 && errno != EEXIST) {
#endif
        perror("mkdir");
        free(dir_path);
        free(file_bytes);
        return 1;
    }

    size_t out_len = strlen(dir_path) + 1u + strlen(safe_name) + 1u;
    char *path = malloc(out_len);
    if (path == NULL) {
        perror("malloc");
        free(dir_path);
        free(file_bytes);
        return 1;
    }
    snprintf(path, out_len, "%s/%s", dir_path, safe_name);

    // If that name is taken, prepend a timestamp instead of overwriting.
    FILE *existing = fopen(path, "rb");
    if (existing != NULL) {
        fclose(existing);
        char unique_name[MAX_INIT_FILENAME + 32];
        snprintf(unique_name, sizeof(unique_name), "%ld_%s", (long)time(NULL), safe_name);
        size_t unique_len = strlen(dir_path) + 1u + strlen(unique_name) + 1u;
        char *unique_path = malloc(unique_len);
        if (unique_path == NULL) {
            perror("malloc");
            free(path);
            free(dir_path);
            free(file_bytes);
            return 1;
        }
        snprintf(unique_path, unique_len, "%s/%s", dir_path, unique_name);
        free(path);
        path = unique_path;
    }

    FILE *out = fopen(path, "wb");
    if (!out) {
        perror("fopen");
        free(path);
        free(dir_path);
        free(file_bytes);
        return 1;
    }
    if (fwrite(file_bytes, 1u, (size_t)total, out) != (size_t)total) {
        perror("fwrite");
        fclose(out);
        free(path);
        free(dir_path);
        free(file_bytes);
        return 1;
    }
    fclose(out);

    printf("Transfer complete: %s\n", path);
    printf("File size: %llu bytes\n", (unsigned long long)total);
    printf("Packets received: %u (+ 1 init + 1 final)\n", session->max_seq);
    printf("Elapsed time: %.3f seconds\n", elapsed_sec);
    printf("Transfer rate: %.2f bytes/sec\n", total / (elapsed_sec > 0.001 ? elapsed_sec : 1));

    free(path);
    free(dir_path);
    free(file_bytes);
    return 0;
}

int main(int argc, char **argv) {
    printf("UDP File Receiver starting...\n");

    // Usage: udp_rx <listen_port> [output_dir] [idle_timeout_ms] [loop]
    // A trailing "loop" keeps the receiver up for multiple transfers (Ctrl+C to stop).
    int loop_mode = 0;
    if (argc >= 2) {
        const char *last = argv[argc - 1];
        if (strcmp(last, "loop") == 0 || strcmp(last, "-l") == 0 || strcmp(last, "--loop") == 0) {
            loop_mode = 1;
            argc--;  // hide the flag from the positional parsing below
        }
    }
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s <listen_port> [output_dir] [idle_timeout_ms] [loop]\n", argv[0]);
        return 1;
    }

    int listen_port = atoi(argv[1]);
    const char *output_dir = argc >= 3 ? argv[2] : ".";
    int idle_timeout_ms = argc >= 4 ? atoi(argv[3]) : 3000;

    printf("Listening on port: %d\n", listen_port);
    printf("Output scope: %s/%s\n", output_dir, RECEIVED_DIR);
    printf("Idle timeout: %d ms\n", idle_timeout_ms);

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    // Dual-stack IPv6 socket (IPV6_V6ONLY off) so it accepts both IPv4
    // (127.0.0.1) and IPv6 (::1) packets, i.e. "localhost" works either way.
    socket_t sock = socket(AF_INET6, SOCK_DGRAM, 0);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
#else
    if (sock < 0) {
#endif
        perror("socket");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    int v6only = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));

    // Windows: disable SIO_UDP_CONNRESET so an ICMP "port unreachable" doesn't
    // make recvfrom() fail with WSAECONNRESET (10054) and spin (see sender).
#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
    BOOL new_behavior = FALSE;
    DWORD bytes_returned = 0;
    WSAIoctl(sock, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior),
             NULL, 0, &bytes_returned, NULL, NULL);
#endif

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;    // listen on all interfaces
    addr.sin6_port = htons((uint16_t)listen_port);

    if (bind(sock, (struct sockaddr *)&addr, (int)sizeof(addr)) != 0) {
        perror("bind");
        socket_close(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    // Short socket timeout so the loop wakes regularly to (re)send NAKs. The
    // longer idle_timeout_ms is the overall "sender went silent" deadline.
#ifdef _WIN32
    DWORD timeout = (DWORD)CTRL_RECV_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
#else
    struct timeval timeout;
    timeout.tv_sec = CTRL_RECV_TIMEOUT_MS / 1000;
    timeout.tv_usec = (CTRL_RECV_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif

    unsigned char buffer[MAX_PACKET_SIZE];
    struct sockaddr_in6 from;  // sender's address (IPv4 or IPv6)
#ifdef _WIN32
    int from_len = (int)sizeof(from);
#else
    socklen_t from_len = (socklen_t)sizeof(from);
#endif
    // Outer loop: one full transfer per iteration (repeats only in loop mode).
    do {
        Session session;
        memset(&session, 0, sizeof(session));
        session.trans_id = 0u;

        double start_time = now_seconds();      // reset once a transfer begins
        double last_progress = now_seconds();   // last packet received (for the deadline)
        double overall_deadline_sec = (double)idle_timeout_ms / 1000.0;

    while (1) {
#ifdef _WIN32
        from_len = (int)sizeof(from);
#else
        from_len = (socklen_t)sizeof(from);
#endif

        // Block for a packet, or wake on the short timeout to (re)send NAKs.
        int received = recvfrom(sock, (char *)buffer, (int)sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);

        if (received > 0) {
            last_progress = now_seconds();  // sender is alive, reset the deadline

            if (handle_packet(&session, buffer, (size_t)received) != 0) {
                fprintf(stderr, "Receiver error while handling packet\n");
                break;
            }

            // Remember where to send control replies (the init packet's sender).
            if (session.have_init && !session.have_sender) {
                session.sender = from;
                session.sender_len = (int)from_len;
                session.have_sender = 1;
                start_time = now_seconds();  // begin timing the actual transfer
            }

            // Send a cumulative ACK. The first one (on init) also advertises
            // "I support windowing"; a windowed sender slides its window on these,
            // a fire-and-forget sender just ignores them.
            if (session.have_init && session.have_sender) {
                advance_ack_base(&session);
                send_ack(sock, &session);
            }

            // Done when we have init + final + every chunk: assemble, verify, ACK.
            if (session.have_init && session.have_final && all_chunks_present(&session)) {
                double elapsed = now_seconds() - start_time;
                if (finish_transfer(&session, output_dir, elapsed) != 0) {
                    break;  // e.g. MD5 mismatch
                }
                // Tell the sender to stop (sent twice in case a COMPLETE is lost).
                send_control(sock, &session, (uint8_t)CTRL_COMPLETE);
                send_control(sock, &session, (uint8_t)CTRL_COMPLETE);
                break;
            }

            // The sender re-sends the final packet to ask "do you have everything?"
            // Answer with a NAK listing the gaps. We trigger ONLY on the final
            // packet, never per data packet, which avoids a NAK storm and a
            // livelock where the sender's finals keep resetting our idle timer.
            if (session.have_sender && (size_t)received >= sizeof(DataHeader)) {
                uint32_t rseq = (uint32_t)buffer[2] << 24 | (uint32_t)buffer[3] << 16 |
                                (uint32_t)buffer[4] << 8 | (uint32_t)buffer[5];
                if (session.have_final && rseq == session.max_seq + 1u) {
                    send_control(sock, &session, (uint8_t)CTRL_NAK);
                }
            }
        } else {
            // Timed out with no packet (every CTRL_RECV_TIMEOUT_MS).
#ifdef _WIN32
            int error_code = WSAGetLastError();
            if (error_code != WSAETIMEDOUT && error_code != WSAEWOULDBLOCK) {
                fprintf(stderr, "recvfrom failed with WSA error %d\n", error_code);
            }
#endif
            // Periodically (re)NAK whatever is still missing (also re-requests a
            // lost final packet) to keep the sender retransmitting.
            if (session.have_init && session.have_sender) {
                send_control(sock, &session, (uint8_t)CTRL_NAK);
            }

            // If the sender has been silent past the deadline, end this attempt.
            if (now_seconds() - last_progress > overall_deadline_sec) {
                if (session.have_init && session.have_final && all_chunks_present(&session)) {
                    double elapsed = now_seconds() - start_time;
                    if (finish_transfer(&session, output_dir, elapsed) == 0) {
                        send_control(sock, &session, (uint8_t)CTRL_COMPLETE);
                    }
                    break;
                }
                if (session.have_init) {
                    fprintf(stderr, "Transfer timed out before completion.\n");
                    break;
                }
                if (loop_mode) {
                    last_progress = now_seconds();  // no sender yet; keep waiting
                    continue;
                }
                fprintf(stderr, "No packets received.\n");
                break;
            }
        }
    }

        free_session(&session);
        if (loop_mode) {
            printf("\n--- Ready for the next transfer on port %d (Ctrl+C to stop) ---\n", listen_port);
            fflush(stdout);
        }
    } while (loop_mode);

    socket_close(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
