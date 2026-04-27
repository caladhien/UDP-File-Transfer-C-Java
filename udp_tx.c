// ========== STANDARD C LIBRARY INCLUDES ==========
#include <errno.h>      // For error codes when system calls fail
#include <stdint.h>     // For fixed-size integer types like uint32_t, uint16_t
#include <stdio.h>      // For file I/O and printf/fprintf functions
#include <stdlib.h>     // For memory allocation and utility functions
#include <string.h>     // For string operations (memcpy, memset, strncpy, etc)
#include <time.h>       // For rand() to generate random transaction IDs

// ========== CROSS-PLATFORM SETUP ==========
// This entire section handles Windows vs Unix/Linux differences
// We use #ifdef to compile the right code for each platform
#ifdef _WIN32
    // ========== WINDOWS-SPECIFIC SETUP ==========
    // Ensure we're targeting Windows Vista or later (for full Winsock2 compatibility)
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
    #endif
    
    // Main Windows Socket API header
    #include <winsock2.h>
    // Extended socket utilities (inet_pton, inet_ntop, etc.)
    #include <ws2tcpip.h>
    // Windows-specific functions
    #include <windows.h>
    
    // Tell MSVC to automatically link against the Winsock library
    #ifdef _MSC_VER
    #pragma comment(lib, "Ws2_32.lib")
    #endif
    
    // Typedef socket_t to SOCKET on Windows (for cross-platform code)
    typedef SOCKET socket_t;
    // Macro to close a socket on Windows
    #define socket_close closesocket
    
    // Windows version of rate limiting (delays between packets)
    // Sleep() is Windows' built-in sleep function
    // We use this to prevent sending packets too fast (which causes buffer overflows)
    static void rate_limit_send(unsigned int delay_ms) {
        if (delay_ms > 0u) {
            Sleep(delay_ms);  // Windows: sleep in milliseconds directly
        }
    }
    
    // Windows version of getting current time
    static double now_seconds(void) { 
        return (double)GetTickCount() / 1000.0;  // GetTickCount() returns milliseconds
    }
    
#else
    // ========== UNIX/LINUX SPECIFIC SETUP ==========
    // These headers provide socket functionality on Unix-like systems
    
    // Internet address operations (htons, inet_addr, etc.)
    #include <arpa/inet.h>
    // File control for non-blocking sockets
    #include <fcntl.h>
    // Socket API
    #include <sys/socket.h>
    // Time structures and functions
    #include <sys/time.h>
    // Standard Unix API (close, etc.)
    #include <unistd.h>
    
    // Typedef socket_t to int on Unix (sockets are just file descriptors)
    typedef int socket_t;
    // Macro to close a socket on Unix
    #define socket_close close
    
    // Unix version of rate limiting (delays between packets)
    // usleep() is Unix's sleep function (takes microseconds)
    // We multiply milliseconds by 1000 to get microseconds
    static void rate_limit_send(unsigned int delay_ms) {
        if (delay_ms > 0u) {
            usleep((useconds_t)delay_ms * 1000u);  // Convert ms to microseconds
        }
    }
    
    // Unix version of getting current time
    static double now_seconds(void) {
        struct timeval tv;  // Struct to hold seconds and microseconds
        gettimeofday(&tv, NULL);  // Get current time from system
        // Convert to a single floating-point value (seconds.microseconds)
        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
    }
#endif

// ========== PROTOCOL CONSTANTS ==========
// Maximum payload data per UDP packet (1400 bytes is safe for most networks)
// Ethernet MTU is typically 1500, minus IP header (20) and UDP header (8) = 1472
// We use 1400 for extra safety margin to avoid fragmentation
#define MAX_DATA_PAYLOAD 1400u

// Filename length constraints (for safety and compatibility)
#define MIN_INIT_FILENAME 1u
#define MAX_INIT_FILENAME 2048u

// MD5 hash is always 16 bytes (128 bits)
#define MD5_DIGEST_LEN 16u

// ========== PACKET STRUCTURE DEFINITIONS ==========
// We use #pragma pack(push, 1) to tell the compiler: DON'T add padding!
// This ensures our binary packets match exactly what the receiver expects
// (In particular, Java's DataOutputStream doesn't add any padding)
#pragma pack(push, 1)

// ===== INIT PACKET HEADER (seq=0, marks start of transfer) =====
// This packet tells the receiver:
//   - Who's sending (transaction ID)
//   - How many data packets are coming (max_seq)
//   - What filename to save as (attached after this header)
typedef struct {
    uint16_t trans_id;  // Unique ID for this transfer session
    uint32_t seq;       // Sequence number = 0 (marks this as the init packet)
    uint32_t max_seq;   // The sequence number of the LAST data packet
} InitHeader;

// ===== DATA PACKET HEADER (seq=1 to max_seq, contains file data) =====
typedef struct {
    uint16_t trans_id;  // Transaction ID (must match init packet's trans_id)
    uint32_t seq;       // Sequence number of this packet (1 to max_seq)
} DataHeader;

// ===== FINAL PACKET (seq=max_seq+1, marks end of transfer) =====
// After all data packets are sent, send this final packet with the MD5 hash
typedef struct {
    uint16_t trans_id;  // Transaction ID (must match init packet's trans_id)
    uint32_t seq;       // Sequence number = max_seq + 1 (signals this is final)
    unsigned char md5[16];  // The MD5 hash of the complete file
} FinalPacket;

// Resume normal struct padding rules from here on
#pragma pack(pop)

// ========== MD5 HASHING ==========
// We implement MD5 ourselves (no external dependencies!)
// MD5 is used to generate a checksum of the file
// The receiver compares its computed MD5 with ours to verify integrity

// This struct holds the running state of an MD5 hash computation
typedef struct {
    uint32_t state[4];          // MD5's 4 internal 32-bit state values
    uint64_t bit_count;         // Total number of bits processed so far
    unsigned char buffer[64];   // Staging area for incomplete 64-byte blocks
} MD5_CTX;

// Helper function: rotate a 32-bit value left by 'count' bits
// This is a fundamental operation in the MD5 algorithm
static uint32_t md5_left_rotate(uint32_t value, uint32_t count) {
    // Shift left by 'count', OR with right-shifted remainder
    return (value << count) | (value >> (32u - count));
}

// Core MD5 transformation function
// This processes one 64-byte block of data and updates the state
static void md5_transform(uint32_t state[4], const unsigned char block[64]) {
    // Start with current state values
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    
    // Extract the 16 32-bit words from the 64-byte block (little-endian)
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) {
        // Combine 4 bytes into one 32-bit word
        x[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

    // MD5 has four auxiliary functions used in different rounds
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
    
    // The STEP macro performs one MD5 transformation step (RFC 1321)
    // Each step: apply a function, add constants/data, rotate, and update
#define STEP(func, a, b, c, d, xk, s, ti) \
    do { \
        (a) += func((b), (c), (d)) + (xk) + (uint32_t)(ti); \
        (a) = md5_left_rotate((a), (s)); \
        (a) += (b); \
    } while (0)

    // ===== ROUND 1: 16 steps using function F =====
    // Each line is one MD5 step with specific rotation amounts and constants
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

    // Clean up the macros (they're only needed for this function)
#undef F
#undef G
#undef H
#undef I
#undef STEP

    // Add the transformed values back to the state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// Initialize a new MD5 hash context
// Call this before hashing any data
static void md5_init(MD5_CTX *ctx) {
    // Set the initial MD5 state (these are standardized constants)
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->bit_count = 0;  // No data processed yet
    memset(ctx->buffer, 0, sizeof(ctx->buffer));  // Clear the staging area
}

// Add data to the hash (can be called multiple times)
// Pass in chunks of file data as we read them
static void md5_update(MD5_CTX *ctx, const unsigned char *input, size_t len) {
    // Find our position in the 64-byte staging buffer (0-63)
    size_t index = (size_t)((ctx->bit_count / 8u) % 64u);
    // Update total bits processed
    ctx->bit_count += (uint64_t)len * 8u;

    // How many bytes until our staging buffer is full?
    size_t part_len = 64u - index;
    size_t i = 0;

    // Do we have enough data to fill and process a complete block?
    if (len >= part_len) {
        // Fill the buffer with new data
        memcpy(&ctx->buffer[index], input, part_len);
        // Process this complete 64-byte block
        md5_transform(ctx->state, ctx->buffer);
        
        // Process any additional complete 64-byte blocks in the input
        for (i = part_len; i + 63u < len; i += 64u) {
            md5_transform(ctx->state, &input[i]);
        }
        index = 0;  // Buffer is now empty
    }

    // Copy any leftover data (less than 64 bytes) into the buffer
    // This will wait here until we get more data or call md5_final
    if (i < len) {
        memcpy(&ctx->buffer[index], &input[i], len - i);
    }
}

// Finish hashing and get the final 16-byte MD5 digest
// This pads the message and processes any remaining data
static void md5_final(MD5_CTX *ctx, unsigned char digest[16]) {
    // MD5 padding starts with 0x80 byte, followed by zeros
    static const unsigned char padding[64] = {0x80};
    
    // Convert total bit count to 8 bytes (little-endian)
    unsigned char length_bytes[8];
    for (int i = 0; i < 8; ++i) {
        length_bytes[i] = (unsigned char)((ctx->bit_count >> (8u * i)) & 0xffu);
    }

    // Calculate how much padding we need
    // Goal: (message_len + padding) mod 64 == 56 (leaves room for 8-byte length)
    size_t index = (size_t)((ctx->bit_count / 8u) % 64u);
    size_t pad_len = (index < 56u) ? (56u - index) : (120u - index);
    
    // Add padding and the original message length
    md5_update(ctx, padding, pad_len);
    md5_update(ctx, length_bytes, 8u);

    // Convert the final state to 16 bytes (the digest)
    // Break each 32-bit state value into 4 bytes (little-endian)
    for (int i = 0; i < 4; ++i) {
        digest[i * 4] = (unsigned char)(ctx->state[i] & 0xffu);
        digest[i * 4 + 1] = (unsigned char)((ctx->state[i] >> 8u) & 0xffu);
        digest[i * 4 + 2] = (unsigned char)((ctx->state[i] >> 16u) & 0xffu);
        digest[i * 4 + 3] = (unsigned char)((ctx->state[i] >> 24u) & 0xffu);
    }
}

// Print an MD5 hash in hexadecimal format
// The hash is printed as 32 hex characters (16 bytes * 2 digits each)
static void print_md5_hex(const unsigned char digest[16]) {
    for (int i = 0; i < 16; ++i) {
        printf("%02x", digest[i]);  // Print each byte as 2-digit hex
    }
    printf("\n");
}

// Extract just the filename from a full path
// Handles both Unix (/path/to/file) and Windows (C:\\path\\to\\file) paths
static const char *basename_from_path(const char *path) {
    const char *base = strrchr(path, '/');    // Look for Unix path separator
    const char *alt = strrchr(path, '\\');    // Look for Windows path separator
    
    // Use whichever separator is found, preferring the rightmost one
    if (!base || (alt && alt > base)) {
        base = alt;
    }
    
    // Return the part after the separator, or the whole path if no separator
    return base ? base + 1 : path;
}

// Parse an IPv4 address string (e.g., "192.168.1.1") into a network address structure
// Returns 1 if successful, 0 if invalid
static int parse_ipv4_address(const char *text, struct in_addr *out) {
#ifdef _WIN32
    // Windows version: use inet_addr (old but widely available)
    unsigned long value = inet_addr(text);
    // inet_addr returns INADDR_NONE for invalid addresses
    // Special case: "255.255.255.255" returns -1 (0xffffffff) which looks like INADDR_NONE
    if (value == INADDR_NONE && strcmp(text, "255.255.255.255") != 0) {
        return 0;  // Invalid address
    }
    out->s_addr = value;
    return 1;  // Success
#else
    // Unix/Linux version: use inet_pton (more modern and safer)
    return inet_pton(AF_INET, text, out) == 1;
#endif
}

// Send a complete UDP packet to the destination
// UDP is either all-or-nothing: either the whole packet sends or it fails
// We verify that the full packet was sent before returning success
static int send_all_packet(socket_t sock, const struct sockaddr_in *addr, const unsigned char *packet, size_t length) {
    // UDP's sendto() is datagram-oriented: it either sends one full packet or fails
    // We still check the return value to catch any OS-level errors
    int sent = sendto(sock, (const char *)packet, (int)length, 0, (const struct sockaddr *)addr, (int)sizeof(*addr));
    
    // Success means the entire packet was sent (sent == length)
    return sent == (int)length ? 0 : -1;
}

// ========== MAIN UDP FILE SENDER LOOP ==========
int main(int argc, char **argv) {
    // ===== PARSE COMMAND-LINE ARGUMENTS =====
    // Usage: udp_tx <dest_ip> <dest_port> <file_path> [pace_ms]
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: %s <dest_ip> <dest_port> <file_path> [pace_ms]\n", argv[0]);
        return 1;  // Incorrect usage
    }

    // Extract command-line parameters
    const char *dest_ip = argv[1];  // Destination IP address to send to (required)
    const int dest_port = atoi(argv[2]);  // Destination UDP port (required)
    const char *file_path = argv[3];  // Path to file to send (required)
    unsigned int pace_ms = (unsigned int)(argc == 5 ? atoi(argv[4]) : 1);  // Delay between packets in ms (optional, default: 1ms)
    const char *filename = basename_from_path(file_path);  // Extract just the filename (no path) for init packet
    const size_t filename_len = strlen(filename);

    // Validate filename length is within acceptable bounds
    if (filename_len < MIN_INIT_FILENAME || filename_len > MAX_INIT_FILENAME) {
        fprintf(stderr, "Filename length must be between %u and %u bytes.\n", MIN_INIT_FILENAME, MAX_INIT_FILENAME);
        return 1;  // Filename too short or too long
    }

    // ===== OPEN AND READ THE FILE =====
    // Open the file in binary read mode
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("fopen");  // Print system error
        return 1;  // Failed to open file
    }

    // ===== GET FILE SIZE =====
    // Seek to the end of file to determine its size
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(file);
        return 1;  // Failed to seek
    }

    // Get the current position (which is the file size)
    long file_size_long = ftell(file);
    if (file_size_long < 0) {
        perror("ftell");
        fclose(file);
        return 1;  // Failed to get file size
    }
    
    // Seek back to the beginning of the file so we can read it
    if (fseek(file, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(file);
        return 1;  // Failed to seek
    }

    // ===== CALCULATE TRANSFER PARAMETERS =====
    uint64_t file_size = (uint64_t)file_size_long;
    // Sequence numbers:
    //   - Seq 0: init packet
    //   - Seq 1 to MaxSeq: data packets (each up to 1400 bytes)
    //   - Seq MaxSeq+1: final packet with MD5
    uint32_t max_seq = (uint32_t)((file_size + MAX_DATA_PAYLOAD - 1u) / MAX_DATA_PAYLOAD);
    
    // Track timing for throughput calculation
    double start_time = now_seconds();
    uint64_t bytes_sent = 0u;  // Count all bytes sent (including headers)

    // ===== INITIALIZE MD5 HASHING =====
    // We compute the MD5 hash as we send the file, so we don't have to read it twice
    MD5_CTX md5;
    md5_init(&md5);

    // ===== WINDOWS-SPECIFIC SETUP =====
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        fclose(file);
        return 1;  // Failed to initialize Winsock
    }
#endif

    // ===== CREATE UDP SOCKET =====
    // AF_INET = IPv4 addresses
    // SOCK_DGRAM = UDP (datagram) socket
    socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    // Check if socket creation succeeded
    #ifdef _WIN32
    if (sock == INVALID_SOCKET) {
    #else
    if (sock < 0) {
    #endif
        perror("socket");  // Print system error
    #ifdef _WIN32
        WSACleanup();  // Clean up Winsock on Windows
    #endif
        fclose(file);
        return 1;  // Failed to create socket
    }

    // ===== SET UP DESTINATION ADDRESS =====
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));  // Clear the struct
    addr.sin_family = AF_INET;  // IPv4
    addr.sin_port = htons((uint16_t)dest_port);  // Convert port to network byte order
    
    // Parse the destination IP address
    if (!parse_ipv4_address(dest_ip, &addr.sin_addr)) {
        fprintf(stderr, "Invalid destination IP address\n");
        socket_close(sock);
    #ifdef _WIN32
        WSACleanup();
    #endif
        fclose(file);
        return 1;  // Invalid IP address
    }

    // ===== GENERATE RANDOM TRANSACTION ID =====
    // Each transfer session gets a unique ID to identify it
    srand((unsigned)time(NULL));  // Seed the random number generator
    uint16_t trans_id = (uint16_t)(rand() & 0xffffu);  // Random 16-bit ID

    // ===== PRINT TRANSFER CONFIGURATION =====
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

    // ===== CORE FIRE-AND-FORGET SEND LOOP =====
    // UDP has NO delivery guarantee + NO ACKs + NO congestion control
    // We just blast packets and hope they arrive! The receiver will detect missing chunks
    // Loop through each data packet, reading from file, hashing, and sending

    for (uint32_t seq = 1; seq <= max_seq; ++seq) {
        // ===== READ CHUNK FROM FILE =====
        // Read up to MAX_DATA_PAYLOAD bytes from the file
        size_t bytes_read = fread(file_buffer, 1u, MAX_DATA_PAYLOAD, file);
        if (bytes_read == 0u && ferror(file)) {
            perror("fread");
            socket_close(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            fclose(file);
            return 1;  // Failed to read file
        }

        // ===== UPDATE MD5 HASH DYNAMICALLY =====
        // We hash the file as we send it chunk-by-chunk
        // This is efficient: no need to read the file from disk a second time!
        md5_update(&md5, file_buffer, bytes_read);

        // ===== BUILD DATA PACKET =====
        // Fill in the sequence number (converted to network byte order)
        data_header.seq = htonl(seq);
        // Copy the data header to the packet buffer
        memcpy(data_packet, &data_header, sizeof(data_header));
        // Copy the file chunk after the header
        memcpy(data_packet + sizeof(data_header), file_buffer, bytes_read);

        // ===== SEND DATA PACKET =====
        // sendto() to the destination address
        if (send_all_packet(sock, &addr, data_packet, sizeof(data_header) + bytes_read) != 0) {
            perror("sendto(data)");
            socket_close(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            fclose(file);
            return 1;  // Failed to send data packet
        }
        bytes_sent += (uint64_t)(sizeof(data_header) + bytes_read);
        
        // ===== RATE LIMITING =====
        // UDP has no backpressure mechanisms, so without rate-limiting,
        // blasting packets in a tight loop would overflow the kernel socket buffer
        // and cause massive packet drops and packet loss
        // By limiting to ~1000 packets/sec (1ms delay), we stay within safe limits
        rate_limit_send(pace_ms);
    }  // End of send loop

    // ===== FINISH MD5 HASHING =====
    // Finalize the MD5 hash to get the 16-byte digest
    unsigned char digest[MD5_DIGEST_LEN];
    md5_final(&md5, digest);

    // ===== BUILD AND SEND FINAL PACKET =====
    // The final packet contains:
    //   - trans_id: same transaction ID as all other packets
    //   - seq: max_seq+1 (one past the last data packet) to indicate this is the final packet
    //   - md5: the 16-byte MD5 hash of the entire file
    FinalPacket final_packet;
    final_packet.trans_id = htons(trans_id);
    final_packet.seq = htonl(max_seq + 1u);  // Special sequence number for final packet
    memcpy(final_packet.md5, digest, sizeof(final_packet.md5));  // Copy MD5 hash

    // ===== SEND FINAL PACKET =====
    // The receiver will check if the received MD5 matches this one
    // If they don't match, the receiver knows some packets were lost or corrupted
    // The hash check will catch any data integrity issues
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

    // ===== PRINT TRANSFER COMPLETION SUMMARY =====
    printf("Transfer sent successfully!\n");
    printf("File MD5 hash: ");
    print_md5_hex(digest);  // Print the 16-byte hash as hex

    // ===== CALCULATE AND PRINT THROUGHPUT =====
    double elapsed_sec = now_seconds() - start_time;
    if (elapsed_sec <= 0.0) {
        elapsed_sec = 0.001;  // Avoid division by zero for very fast transfers
    }
    printf("Total bytes sent (including protocol headers): %llu\n", (unsigned long long)bytes_sent);
    printf("Elapsed time: %.3f seconds\n", elapsed_sec);
    printf("Average throughput: %.2f bytes/sec\n", (double)file_size / elapsed_sec);

    // ===== CLEANUP AND EXIT =====
    // Close the UDP socket
    socket_close(sock);
    
    // Clean up Winsock on Windows (no-op on Linux)
#ifdef _WIN32
    WSACleanup();
#endif
    
    // Close the file handle
    fclose(file);
    
    // Success!
    return 0;
}