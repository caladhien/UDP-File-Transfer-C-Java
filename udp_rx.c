#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// cross-platform headers

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <direct.h>
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif
typedef SOCKET socket_t;
#define socket_close closesocket
#ifdef _WIN32
static double now_seconds(void) { return (double)GetTickCount() / 1000.0; }
#endif
#else
#include <arpa/inet.h>
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

#define MAX_DATA_PAYLOAD 1400u
#define MIN_INIT_FILENAME 8u
#define MAX_INIT_FILENAME 2048u
#define MAX_PACKET_SIZE 4096u
#define MD5_DIGEST_LEN 16u
#define RECEIVED_DIR "received_files"


// disables C compiler padding to force strict alignment
// so the receiver parses offsets exactly as they were packaged by Java
#pragma pack(push, 1)
typedef struct {
    uint16_t trans_id;
    uint32_t seq;
    uint32_t max_seq;
} InitHeader;

typedef struct {
    uint16_t trans_id;
    uint32_t seq;
} DataHeader;

typedef struct {
    uint16_t trans_id;
    uint32_t seq;
    unsigned char md5[16];
} FinalPacket;
#pragma pack(pop)

// embedded the MD5 logic to maintain zero external dependencies

typedef struct {
    uint32_t state[4];
    uint64_t bit_count;
    unsigned char buffer[64];
} MD5_CTX;


// because UDP can reorder packets, not possible to write linearly
// using chunk struct to hold each packet's payload in memory
// indexed by the sequence number to be brought together later
typedef struct {
    unsigned char *data;
    uint32_t length;
    uint8_t present;
} Chunk;

typedef struct {
    uint16_t trans_id;
    uint32_t max_seq;
    char *filename;
    Chunk *chunks;
    unsigned char final_md5[16];
    uint8_t have_init;
    uint8_t have_final;
} Session;

static uint32_t md5_left_rotate(uint32_t value, uint32_t count) {
    return (value << count) | (value >> (32u - count));
}

static void md5_transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t x[16];

    for (int i = 0; i < 16; ++i) {
        x[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

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

static void md5_update(MD5_CTX *ctx, const unsigned char *input, size_t len) {
    size_t index = (size_t)((ctx->bit_count / 8u) % 64u);
    ctx->bit_count += (uint64_t)len * 8u;

    size_t part_len = 64u - index;
    size_t i = 0;

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

static void md5_final(MD5_CTX *ctx, unsigned char digest[16]) {
    static const unsigned char padding[64] = {0x80};
    unsigned char length_bytes[8];
    for (int i = 0; i < 8; ++i) {
        length_bytes[i] = (unsigned char)((ctx->bit_count >> (8u * i)) & 0xffu);
    }

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

static const char *basename_from_path(const char *path) {
    const char *base = strrchr(path, '/');
    const char *alt = strrchr(path, '\\');
    if (!base || (alt && alt > base)) {
        base = alt;
    }
    return base ? base + 1 : path;
}

static int ensure_chunks(Session *session) {
    if (session->chunks == NULL) {
        session->chunks = calloc((size_t)session->max_seq + 1u, sizeof(Chunk));
        if (session->chunks == NULL) {
            return -1;
        }
    }
    return 0;
}


// catch and sort the UDP stream
// parse out the sequence index, copy the payload into the sessionmap if valid
// arrival order is ignored
static int handle_packet(Session *session, const unsigned char *data, size_t length) {
    if (length < sizeof(DataHeader)) {
        return 0;
    }

    // convert back from Network Byte Order for the C machine
    uint16_t trans_id = (uint16_t)((data[0] << 8) | data[1]);
    uint32_t seq = (uint32_t)data[2] << 24 | (uint32_t)data[3] << 16 | (uint32_t)data[4] << 8 | (uint32_t)data[5];

    if (!session->have_init) {

        // safety check.
        // can't do anything until Seq=0 (init) is reached
        // filename and max_seq needs to allocate the memory correctly
        if (seq != 0u || length < sizeof(InitHeader)) {
            return 0;
        }

        uint32_t max_seq = (uint32_t)data[6] << 24 | (uint32_t)data[7] << 16 | (uint32_t)data[8] << 8 | (uint32_t)data[9];
        size_t filename_len = length - sizeof(InitHeader);
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

    if (trans_id != session->trans_id) {
        return 0;
    }

    // Seq = MaxSeq + 1 means this is the final packet
    // stashing the sender's MD5 hash here
    // not verified until all data chunks have arrived

    if (seq == session->max_seq + 1u && length == sizeof(FinalPacket)) {
        memcpy(session->final_md5, data + 6, 16u);
        session->have_final = 1;
        return 0;
    }

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

    // handling out-of-order delivery
    // if the chunk isn't received yet, copy it to its exact spot in the array
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


// this runs when the timeout triggers or when the Final packet is visible
// chunks are brought together strictly in ascending sequence order
// assembled file's hash is computed
// and compared against the sender's
static void print_md5_hex(const unsigned char *digest, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

static int finish_transfer(Session *session, const char *output_dir, double elapsed_sec) {
    if (!(session->have_init && session->have_final && session->chunks != NULL)) {
        fprintf(stderr, "Transfer incomplete.\n");
        return 1;
    }

    uint64_t total = 0;
    for (uint32_t seq = 1; seq <= session->max_seq; ++seq) {
        if (!session->chunks[seq].present) {
            fprintf(stderr, "Missing chunk %u\n", seq);
            return 1;
        }
        total += session->chunks[seq].length;
    }

    if (total > 2147483647u) {
        fprintf(stderr, "File too large to assemble in memory.\n");
        return 1;
    }

    unsigned char *file_bytes = malloc((size_t)total);
    if (file_bytes == NULL) {
        perror("malloc");
        return 1;
    }

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

    printf("MD5 received: ");
    print_md5_hex(session->final_md5, MD5_DIGEST_LEN);
    printf("MD5 computed: ");
    print_md5_hex(computed, MD5_DIGEST_LEN);

    if (memcmp(computed, session->final_md5, MD5_DIGEST_LEN) != 0) {
        fprintf(stderr, "MD5 mismatch. Transfer corrupted.\n");
        free(file_bytes);
        return 1;
    }


    // Save to RECEIVED_DIR/<filename>
    const char *base = basename_from_path(session->filename);
    char safe_name[MAX_INIT_FILENAME + 1];
    strncpy(safe_name, base ? base : "received.bin", MAX_INIT_FILENAME);
    safe_name[MAX_INIT_FILENAME] = '\0';
    if (strlen(safe_name) == 0) {
        strcpy(safe_name, "received.bin");
    }

    size_t dir_len = strlen(output_dir) + 1u + strlen(RECEIVED_DIR) + 1u;
    char *dir_path = malloc(dir_len);
    if (dir_path == NULL) {
        perror("malloc");
        free(file_bytes);
        return 1;
    }
    snprintf(dir_path, dir_len, "%s/%s", output_dir, RECEIVED_DIR);

    // Ensure base output scope exists first (e.g. "recv_c").
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

    // Ensure directory exists
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

    // Prevent accidental overwrite by adding a time suffix when the path already exists.
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
    printf("Packets received: %u\n", session->max_seq);
    printf("Elapsed time: %.3f seconds\n", elapsed_sec);
    printf("Transfer rate: %.2f bytes/sec\n", total / (elapsed_sec > 0.001 ? elapsed_sec : 1));
    free(path);
    free(dir_path);
    free(file_bytes);
    return 0;
}

int main(int argc, char **argv) {
    printf("UDP File Receiver starting...\n");
    double start_time = now_seconds();

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s <listen_port> [output_dir] [idle_timeout_ms]\n", argv[0]);
        return 1;
    }

    int listen_port = atoi(argv[1]);
    const char *output_dir = argc >= 3 ? argv[2] : ".";
    int idle_timeout_ms = argc >= 4 ? atoi(argv[3]) : 3000;

    printf("Listening on port: %d\n", listen_port);
    printf("Output scope: %s/%s\n", output_dir, RECEIVED_DIR);
    printf("Idle timeout: %d ms\n", idle_timeout_ms);

    // UDP gives zero delivery guarantee + no ACKs
    // a dropped packet will result in the RX waiting forever for a chunk
    // that isn't coming
    // setting a timeout to abort incomplete transfers safely
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
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

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)listen_port);

    if (bind(sock, (struct sockaddr *)&addr, (int)sizeof(addr)) != 0) {
        perror("bind");
        socket_close(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    Session session;
    memset(&session, 0, sizeof(session));
    session.trans_id = 0u;

#ifdef _WIN32
    DWORD timeout = (DWORD)idle_timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
#else
    struct timeval timeout;
    timeout.tv_sec = idle_timeout_ms / 1000;
    timeout.tv_usec = (idle_timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif

    unsigned char buffer[MAX_PACKET_SIZE];
    struct sockaddr_in from;
#ifdef _WIN32
    int from_len = (int)sizeof(from);
#else
    socklen_t from_len = (socklen_t)sizeof(from);
#endif
    int have_activity = 0;

    while (1) {
#ifdef _WIN32
        from_len = (int)sizeof(from);
#else
        from_len = (socklen_t)sizeof(from);
#endif
        int received = recvfrom(sock, (char *)buffer, (int)sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);
        if (received > 0) {
            have_activity = 1;
            if (handle_packet(&session, buffer, (size_t)received) != 0) {
                fprintf(stderr, "Receiver error while handling packet\n");
                break;
            }
            if (session.have_init && session.have_final) {
                double elapsed = now_seconds() - start_time;
                if (finish_transfer(&session, output_dir, elapsed) != 0) {
                    break;
                }
                break;
            }
        } else {
#ifdef _WIN32
            int error_code = WSAGetLastError();
            if (error_code != WSAETIMEDOUT && error_code != WSAEWOULDBLOCK) {
                fprintf(stderr, "recvfrom failed with WSA error %d\n", error_code);
            }
#endif
            if (have_activity) {
                fprintf(stderr, "Transfer timed out before completion.\n");
            } else {
                fprintf(stderr, "No packets received.\n");
            }
            break;
        }
    }

    free_session(&session);
    socket_close(sock);
#ifdef _WIN32
    WSACleanup();
#endif
        return 0;
}
