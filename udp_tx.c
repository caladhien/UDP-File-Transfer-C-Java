#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Cross platform boilerplate so it compiles both on MinGW and Linux/Mac.
// rate_limit_send() to prevent buffer overflows later
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
static double now_seconds(void) { return (double)GetTickCount() / 1000.0; }
#else
#include <arpa/inet.h>
#include <fcntl.h>
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

// Capping payload at 1400 bytes, typical MTU is 1500.
// Keeping the payload at 1400 leaves plenty of room for IP and UDP
// headers and reduces packet fragmentation chance
#define MAX_DATA_PAYLOAD 1400u
#define MIN_INIT_FILENAME 8u
#define MAX_INIT_FILENAME 2048u
#define MD5_DIGEST_LEN 16u

// required for cross-language compatibility
// C compilers insert unseen padding bytes to align memory efficiently
// but Java doesn't know about them, expects exact offsets
// pragma here forces C to pack the struct tight in a way that the byte stream
// matches Java's expectations
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

typedef struct {
    uint32_t state[4];
    uint64_t bit_count;
    unsigned char buffer[64];
} MD5_CTX;

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
// Single MD5 round step (RFC 1321 core operation).
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

static void print_md5_hex(const unsigned char digest[16]) {
    for (int i = 0; i < 16; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

static const char *basename_from_path(const char *path) {
    const char *base = strrchr(path, '/');
    const char *alt = strrchr(path, '\\');
    if (!base || (alt && alt > base)) {
        base = alt;
    }
    return base ? base + 1 : path;
}

static int parse_ipv4_address(const char *text, struct in_addr *out) {
#ifdef _WIN32
    unsigned long value = inet_addr(text);
    if (value == INADDR_NONE && strcmp(text, "255.255.255.255") != 0) {
        return 0;
    }
    out->s_addr = value;
    return 1;
#else
    return inet_pton(AF_INET, text, out) == 1;
#endif
}

static int send_all_packet(socket_t sock, const struct sockaddr_in *addr, const unsigned char *packet, size_t length) {
    // UDP sendto() is oriented datagram wise
    // it should either send one full packet or fail
    // length is still checked to fail fast if the OS is acting weird
    int sent = sendto(sock, (const char *)packet, (int)length, 0, (const struct sockaddr *)addr, (int)sizeof(*addr));
    return sent == (int)length ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: %s <dest_ip> <dest_port> <file_path> [pace_ms]\n", argv[0]);
        return 1;
    }

    const char *dest_ip = argv[1];
    const int dest_port = atoi(argv[2]);
    const char *file_path = argv[3];
    unsigned int pace_ms = (unsigned int)(argc == 5 ? atoi(argv[4]) : 1);
    const char *filename = basename_from_path(file_path);
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

    uint64_t file_size = (uint64_t)file_size_long;
    /*
     * Seq numbers are logical chunk indices:
     *   Seq=1 .. MaxSeq => data chunks
     *   Seq=0           => init packet
     *   Seq=MaxSeq+1    => final packet with MD5
     */
    uint32_t max_seq = (uint32_t)((file_size + MAX_DATA_PAYLOAD - 1u) / MAX_DATA_PAYLOAD);
    double start_time = now_seconds();
    uint64_t bytes_sent = 0u;

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
        fclose(file);
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)dest_port);
        if (!parse_ipv4_address(dest_ip, &addr.sin_addr)) {
        fprintf(stderr, "Invalid destination IP address\n");
        socket_close(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        fclose(file);
        return 1;
    }

    srand((unsigned)time(NULL));
    uint16_t trans_id = (uint16_t)(rand() & 0xffffu);

    printf("Starting UDP transfer\n");
    printf("Destination: %s:%d\n", dest_ip, dest_port);
    printf("File: %s (%llu bytes)\n", filename, (unsigned long long)file_size);
    printf("Transaction ID: %u\n", (unsigned)trans_id);
    printf("Data packets: %u\n", max_seq);
    printf("Packet pacing: %u ms\n", pace_ms);

    // convert all headers to Big Endian (Network Byte Order) using htons/htonl
    // for interoperability. sending from a little-endian x86 to java directly
    // would break completely.
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

    unsigned char file_buffer[MAX_DATA_PAYLOAD];
    unsigned char data_packet[sizeof(DataHeader) + MAX_DATA_PAYLOAD];
    DataHeader data_header;
    data_header.trans_id = htons(trans_id);

    // core fire-and-forget loop
    // no ACKs and no congestion control

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

        // update the MD5 hash dynamically chunk-by-chunk
        // no need to read the whole file a second time from the HD
        md5_update(&md5, file_buffer, bytes_read);

        data_header.seq = htonl(seq);
        memcpy(data_packet, &data_header, sizeof(data_header));
        memcpy(data_packet + sizeof(data_header), file_buffer, bytes_read);

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
        
        // Rate Limiting
        // because UDP has no mechanisms for backpressure, without the rate-limiting,
        // blasting the packets in a tight while-loop would cause instant overflow
        // and OC socket would buffer
        // with mass packet drops
        rate_limit_send(pace_ms);
    }

    unsigned char digest[MD5_DIGEST_LEN];
    md5_final(&md5, digest);

    FinalPacket final_packet;
    final_packet.trans_id = htons(trans_id);
    final_packet.seq = htonl(max_seq + 1u);
    memcpy(final_packet.md5, digest, sizeof(final_packet.md5));

    // transport MD5 digest
    // if any bytes were dropped or corrupted during fire-and-forget
    // the hash check will catch it here
    if (send_all_packet(sock, &addr, (const unsigned char *)&final_packet, sizeof(final_packet)) != 0) {
        perror("sendto(final)");
        socket_close(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        fclose(file);
        return 1;
    }
    bytes_sent += (uint64_t)sizeof(final_packet);

    printf("Transfer sent. File MD5: ");
    print_md5_hex(digest);

    double elapsed_sec = now_seconds() - start_time;
    if (elapsed_sec <= 0.0) {
        elapsed_sec = 0.001;
    }
    printf("Bytes sent (including protocol headers): %llu\n", (unsigned long long)bytes_sent);
    printf("Elapsed time: %.3f seconds\n", elapsed_sec);
    printf("Average throughput: %.2f bytes/sec\n", (double)file_size / elapsed_sec);

    socket_close(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    fclose(file);
    return 0;
}