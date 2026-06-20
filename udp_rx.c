// ========== STANDARD C LIBRARY INCLUDES ==========
#include <errno.h>      // For error codes when system calls fail
#include <stdint.h>     // For fixed-size integer types like uint32_t, uint16_t
#include <stdio.h>      // For file I/O and printf/fprintf functions
#include <stdlib.h>     // For memory allocation (malloc, free) and utility functions
#include <string.h>     // For string operations (memcpy, memset, strncpy, etc)
#include <time.h>       // For time() function to generate unique filenames

// ========== CROSS-PLATFORM SPECIFIC HEADERS ==========
// We need different socket libraries and utilities depending on Windows vs Unix/Linux

#ifdef _WIN32
    // ========== WINDOWS-SPECIFIC SETUP ==========
    // This entire section sets up the Windows Socket API (Winsock2)
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
    // Directory creation on Windows (_mkdir)
    #include <direct.h>
    
    // Tell MSVC to automatically link against the Winsock library
    #ifdef _MSC_VER
    #pragma comment(lib, "Ws2_32.lib")
    #endif
    
    // Typedef socket_t to SOCKET on Windows (for cross-platform code)
    typedef SOCKET socket_t;
    // Macro to close a socket on Windows (different from Unix)
    #define socket_close closesocket
    
    // Windows version of getting current time in seconds
    // GetTickCount() returns milliseconds since boot
    #ifdef _WIN32
    static double now_seconds(void) { 
        return (double)GetTickCount() / 1000.0; 
    }
    #endif
    
#else
    // ========== UNIX/LINUX SPECIFIC SETUP ==========
    // These headers provide socket functionality on Unix-like systems
    
    // Internet address operations (htons, inet_addr, etc.)
    #include <arpa/inet.h>
    // IPv6 address structures and constants
    #include <netinet/in.h>
    // File stat/mode definitions
    #include <sys/stat.h>
    // Socket API
    #include <sys/socket.h>
    // Time structures and functions
    #include <sys/time.h>
    // Standard Unix API (close, mkdir, etc.)
    #include <unistd.h>
    
    // Typedef socket_t to int on Unix (sockets are just file descriptors)
    typedef int socket_t;
    // Macro to close a socket on Unix (uses standard close() function)
    #define socket_close close
    
    // Unix version of getting current time
    // gettimeofday() gives us seconds + microseconds precision
    static double now_seconds(void) {
        struct timeval tv;  // Struct to hold seconds and microseconds
        gettimeofday(&tv, NULL);  // Get current time from system
        // Convert to a single floating-point value (seconds.microseconds)
        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
    }
#endif

// ========== PROTOCOL CONSTANTS ==========
// These define the limits and structure of our UDP file transfer protocol

// Maximum payload data per UDP packet (1400 bytes is safe for most networks)
// Ethernet MTU is typically 1500, minus IP header (20) and UDP header (8) = 1472
// We use 1400 for extra safety margin
#define MAX_DATA_PAYLOAD 1400u

// Filename length must be at least this long (minimum 8 chars for safety)
#define MIN_INIT_FILENAME 1u

// Filename cannot exceed this length (2048 is reasonable limit)
#define MAX_INIT_FILENAME 2048u

// Largest UDP packet we'll accept (includes all headers)
#define MAX_PACKET_SIZE 4096u

// MD5 hash is always 16 bytes (128 bits)
#define MD5_DIGEST_LEN 16u

// Directory where we save received files
#define RECEIVED_DIR "received_files"

// ========== CONTROL CHANNEL (RX -> TX) CONSTANTS ==========
// We send these small control packets back to the sender so it can retransmit
// anything we are missing (NAK) or stop once we have verified the file (COMPLETE).
#define CTRL_NAK 0u        // "resend these data seqs, then resend the final packet"
#define CTRL_COMPLETE 1u   // "all data received and MD5 verified, you may stop"
#define CTRL_ACK 2u        // cumulative ACK: "I have everything below ack_base contiguously"

// Largest number of missing seqs we list inside one NAK packet. We give the seq
// list the same byte budget as a data packet's payload (MAX_DATA_PAYLOAD), so a
// NAK datagram (5 + 4*N) stays the same MTU-safe size as a data packet:
// 1400/4 = 350 seqs -> 5 + 1400 = 1405 bytes.
#define MAX_NAK_SEQS (MAX_DATA_PAYLOAD / 4u)

// Short socket timeout (ms) so the receive loop wakes up regularly to (re)send NAKs.
#define CTRL_RECV_TIMEOUT_MS 500


// ========== PACKET STRUCTURE DEFINITIONS ==========
// We use #pragma pack(push, 1) to tell the compiler: DON'T add padding between struct members!
// This ensures our binary packets match exactly what the Java sender creates.
// Different compilers can add padding for alignment, which would mess up our parsing.
// By forcing 1-byte packing, every field is exactly where we expect it.
#pragma pack(push, 1)

// ===== INIT PACKET HEADER (seq=0, marks start of transfer) =====
// This packet tells the receiver:
//   - Who's sending (transaction ID)
//   - How many data packets are coming (max_seq)
//   - What filename to save as (attached after this header)
typedef struct {
    uint16_t trans_id;  // Unique ID for this transfer session
    uint32_t seq;       // Sequence number = 0 (marks this as the init packet)
    uint32_t max_seq;   // The sequence number of the LAST data packet (so total packets = max_seq)
} InitHeader;

// ===== DATA PACKET HEADER (seq=1 to max_seq, contains file data) =====
// Each regular data packet has:
//   - Transaction ID (must match the init packet)
//   - Sequence number (1, 2, 3, ... up to max_seq)
//   - Followed by up to 1400 bytes of actual file data
typedef struct {
    uint16_t trans_id;  // Transaction ID (must match init packet's trans_id)
    uint32_t seq;       // Sequence number of this packet (1 to max_seq)
} DataHeader;

// ===== FINAL PACKET (seq=max_seq+1, marks end of transfer) =====
// After all data packets arrive, the sender sends this final packet with:
//   - Transaction ID
//   - Sequence number = max_seq + 1 (signals this is the final packet)
//   - The MD5 hash of the complete file (for verification)
typedef struct {
    uint16_t trans_id;  // Transaction ID (must match init packet's trans_id)
    uint32_t seq;       // Sequence number = max_seq + 1 (marks this as final)
    unsigned char md5[16];  // The sender's computed MD5 hash of the complete file
} FinalPacket;

// Resume normal struct padding rules from here on
#pragma pack(pop)

// ========== MD5 HASHING UTILITIES ==========
// We implement MD5 ourselves (no external dependencies!)
// MD5 is used to verify that the received file matches what the sender transmitted

// This struct holds the running state of an MD5 hash computation
// We update it incrementally as we receive file data
typedef struct {
    uint32_t state[4];          // MD5's 4 internal 32-bit state values
    uint64_t bit_count;         // Total number of bits processed so far
    unsigned char buffer[64];   // Staging area for incomplete 64-byte blocks
} MD5_CTX;


// ========== FILE REASSEMBLY STRUCTURES ==========
// KEY INSIGHT: UDP can deliver packets OUT OF ORDER!
// So we can't just write to the file as packets arrive.
// Instead, we store each packet in its correct position.

// Represents one piece (chunk) of the file
typedef struct {
    unsigned char *data;   // The actual file data in this chunk
    uint32_t length;       // How many bytes are in this chunk
    uint8_t present;       // Flag: 1 = we have this chunk, 0 = still waiting for it
} Chunk;

// Represents one complete file transfer session
// (A session = one file being transferred from sender to receiver)
typedef struct {
    uint16_t trans_id;           // The transaction ID of this transfer
    uint32_t max_seq;            // The sequence number of the last data packet
    char *filename;              // The filename to save as (sent by transmitter)
    Chunk *chunks;               // Array of all file chunks [0 to max_seq]
                                 // chunks[0] is unused; data packets are 1 to max_seq
    unsigned char final_md5[16]; // MD5 hash sent by the sender (for verification)
    uint8_t have_init;           // Flag: 1 = init packet arrived, 0 = not yet
    uint8_t have_final;          // Flag: 1 = final packet arrived, 0 = not yet

    struct sockaddr_in6 sender;  // Address of the sender (where we send control replies)
    int sender_len;              // Length of the sender address
    uint8_t have_sender;         // Flag: 1 = we know the sender's address

    uint32_t ack_base;           // Lowest seq still missing (cumulative ACK point).
                                 // Everything in 1..ack_base-1 has arrived contiguously.
} Session;

static uint32_t md5_left_rotate(uint32_t value, uint32_t count) {
    return (value << count) | (value >> (32u - count));
}

// Core MD5 transformation function
// This processes one 64-byte block of data and updates the state
// MD5 splits input into 64-byte chunks and transforms them in rounds
static void md5_transform(uint32_t state[4], const unsigned char block[64]) {
    // Start with current state values
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    
    // Extract the 16 32-bit words from the 64-byte block
    // Note: MD5 uses little-endian format
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) {
        // Combine 4 bytes into one 32-bit word (little-endian)
        x[i] = (uint32_t)block[i * 4] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

    // MD5 has four auxiliary functions used in different rounds
    // F, G, H, I each perform bitwise operations on 3 values
    // These are the standard MD5 auxiliary functions
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
    
    // The STEP macro performs one MD5 transformation step
    // Each step:
    //   1. Applies an auxiliary function
    //   2. Adds a constant and a data word
    //   3. Rotates the result
    //   4. Adds it back to one of the state values
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

    // ===== ROUND 4: 16 steps using function I =====
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
    // This is how MD5 accumulates changes across multiple blocks
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
// Pass in chunks of file data as they arrive
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

// ========== SESSION MANAGEMENT UTILITIES ==========

// Clean up all memory used by a session
// Call this when a transfer completes or fails
static void free_session(Session *session) {
    // Free all the file chunks we received
    if (session->chunks != NULL) {
        // Loop through each possible chunk (0 to max_seq)
        // Note: chunk 0 is unused, but we free it anyway for simplicity
        for (uint32_t i = 0; i <= session->max_seq; ++i) {
            free(session->chunks[i].data);  // Free the actual file data
        }
        free(session->chunks);  // Free the chunk array itself
    }
    
    free(session->filename);  // Free the filename string
    memset(session, 0, sizeof(*session));  // Clear the entire struct
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

// Allocate the chunks array if it doesn't exist yet
// max_seq tells us how many chunks to allocate
static int ensure_chunks(Session *session) {
    if (session->chunks == NULL) {
        // Allocate space for chunks 0 through max_seq (max_seq + 1 total)
        // calloc() allocates AND initializes all bytes to zero
        session->chunks = calloc((size_t)session->max_seq + 1u, sizeof(Chunk));
        if (session->chunks == NULL) {
            return -1;  // Allocation failed
        }
    }
    return 0;  // Success
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

// Check whether every data chunk (1..max_seq) has arrived.
static int all_chunks_present(const Session *session) {
    if (session->chunks == NULL) {
        return 0;
    }
    for (uint32_t seq = 1; seq <= session->max_seq; ++seq) {
        if (!session->chunks[seq].present) {
            return 0;  // Still missing at least one chunk
        }
    }
    return 1;  // All chunks present
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
        // List the missing data sequence numbers (big-endian)
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


// ========== PACKET HANDLING ==========
// This function processes incoming UDP packets
// It handles three types: INIT (seq=0), DATA (seq 1-N), and FINAL (seq=N+1)
// Returns: 0 = normal, -1 = error, ignores invalid packets
static int handle_packet(Session *session, const unsigned char *data, size_t length) {
    // Packets must be at least 6 bytes (trans_id + seq header)
    if (length < sizeof(DataHeader)) {
        return 0;  // Too small, ignore
    }

    // Extract the transaction ID and sequence number from the packet header
    // Note: Network byte order = big-endian, so highest byte comes first
    uint16_t trans_id = (uint16_t)((data[0] << 8) | data[1]);
    uint32_t seq = (uint32_t)data[2] << 24 | (uint32_t)data[3] << 16 | (uint32_t)data[4] << 8 | (uint32_t)data[5];

    // ===== HANDLE INIT PACKET (seq=0) =====
    // The init packet tells us the filename and max sequence number
    if (!session->have_init) {
        // Safety check: we MUST receive seq=0 first (the init packet)
        // And it must be large enough to contain the full init header
        if (seq != 0u || length < sizeof(InitHeader)) {
            return 0;  // Not the init packet, ignore it
        }

        // Extract max_seq (tells us how many data packets are coming)
        uint32_t max_seq = (uint32_t)data[6] << 24 | (uint32_t)data[7] << 16 | (uint32_t)data[8] << 8 | (uint32_t)data[9];
        
        // The filename starts after the header
        // Its length = total packet length - header size
        size_t filename_len = length - sizeof(InitHeader);
        
        // Filename must be within reasonable bounds
        if (filename_len < MIN_INIT_FILENAME || filename_len > MAX_INIT_FILENAME) {
            return 0;  // Invalid filename size, ignore
        }

        // Allocate space for the filename (+ 1 for null terminator)
        char *filename = malloc(filename_len + 1u);
        if (filename == NULL) {
            return -1;  // Out of memory error
        }
        
        // Copy the filename from the packet
        memcpy(filename, data + sizeof(InitHeader), filename_len);
        filename[filename_len] = '\0';  // Null-terminate the string

        // Store this session's initialization info
        session->trans_id = trans_id;
        session->max_seq = max_seq;
        session->filename = filename;
        session->have_init = 1;

        // Allocate the chunks array now that we know how many chunks to expect
        if (ensure_chunks(session) != 0) {
            return -1;  // Memory allocation failed
        }
        return 0;  // Successfully processed init packet
    }

    // ===== FROM HERE ON: IGNORE PACKETS FROM OTHER SENDERS =====
    // Make sure this packet is from the same sender (matching transaction ID)
    if (trans_id != session->trans_id) {
        return 0;  // Different sender, ignore
    }

    // ===== HANDLE FINAL PACKET (seq=max_seq+1) =====
    // This packet signals the end of transmission and contains the MD5 checksum
    if (seq == session->max_seq + 1u && length == sizeof(FinalPacket)) {
        // Extract and store the sender's MD5 hash
        memcpy(session->final_md5, data + 6, 16u);
        session->have_final = 1;
        return 0;  // Final packet received successfully
    }

    // ===== HANDLE DATA PACKETS (seq 1 to max_seq) =====
    // Sanity check: sequence number must be in valid range
    if (seq == 0u || seq > session->max_seq) {
        return 0;  // Invalid sequence number, ignore
    }

    // Extract the payload (everything after the header)
    size_t payload_len = length - sizeof(DataHeader);
    
    // Make sure the payload isn't unreasonably large
    if (payload_len > MAX_DATA_PAYLOAD) {
        return 0;  // Packet too large, ignore
    }

    // Ensure the chunks array is ready (should already be, but check anyway)
    if (session->chunks == NULL && ensure_chunks(session) != 0) {
        return -1;  // Memory allocation failed
    }

    // ===== HANDLE OUT-OF-ORDER DELIVERY =====
    // UDP can deliver packets in any order, so we store each chunk at its correct position
    // Only store the chunk if we haven't received it yet (avoid storing duplicates)
    if (!session->chunks[seq].present) {
        // Allocate memory for this chunk's data
        unsigned char *copy = malloc(payload_len);
        if (copy == NULL) {
            return -1;  // Out of memory error
        }
        
        // Copy the payload data into our buffer
        memcpy(copy, data + sizeof(DataHeader), payload_len);
        
        // Store the chunk at its correct sequence position
        session->chunks[seq].data = copy;
        session->chunks[seq].length = (uint32_t)payload_len;
        session->chunks[seq].present = 1;  // Mark this chunk as received
    }

    return 0;  // Packet processed successfully
}


// ========== FILE FINALIZATION ==========
// Helper function to print a hash in hexadecimal format
// MD5 hashes are printed as 32 hex characters (16 bytes = 16 * 2 digits)
static void print_md5_hex(const unsigned char *digest, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", digest[i]);  // Print each byte as 2-digit hex
    }
    printf("\n");  // Newline after the hash
}

// Assemble all received chunks into a complete file
// Verify the MD5 checksum against what the sender provided
// Save the file to disk if everything checks out
static int finish_transfer(Session *session, const char *output_dir, double elapsed_sec) {
    // Sanity checks: do we have all the pieces?
    if (!(session->have_init && session->have_final && session->chunks != NULL)) {
        fprintf(stderr, "Transfer incomplete.\n");
        return 1;  // Transfer failed
    }

    // Check that all expected chunks arrived
    // (if any chunk is missing, return error)
    uint64_t total = 0;
    for (uint32_t seq = 1; seq <= session->max_seq; ++seq) {
        if (!session->chunks[seq].present) {
            fprintf(stderr, "Missing chunk %u\n", seq);
            return 1;  // Chunk missing, file is incomplete
        }
        total += session->chunks[seq].length;
    }

    // Check that the total file size is reasonable (fits in 32-bit signed int)
    if (total > 2147483647u) {
        fprintf(stderr, "File too large to assemble in memory.\n");
        return 1;  // File is too large
    }

    // Allocate memory to hold the entire assembled file
    unsigned char *file_bytes = malloc((size_t)total);
    if (file_bytes == NULL) {
        perror("malloc");
        return 1;  // Memory allocation failed
    }

    // ===== ASSEMBLE AND HASH =====
    // Start a fresh MD5 hash computation
    MD5_CTX md5;
    md5_init(&md5);

    // Copy all chunks into one contiguous buffer
    // and compute the MD5 hash as we go
    size_t offset = 0;
    for (uint32_t seq = 1; seq <= session->max_seq; ++seq) {
        // Copy this chunk to its position in the file
        memcpy(file_bytes + offset, session->chunks[seq].data, session->chunks[seq].length);
        // Add this chunk's data to the MD5 hash
        md5_update(&md5, session->chunks[seq].data, session->chunks[seq].length);
        offset += session->chunks[seq].length;
    }

    // Finalize the MD5 hash
    unsigned char computed[MD5_DIGEST_LEN];
    md5_final(&md5, computed);

    // ===== VERIFY MD5 CHECKSUM =====
    printf("MD5 received: ");
    print_md5_hex(session->final_md5, MD5_DIGEST_LEN);
    printf("MD5 computed: ");
    print_md5_hex(computed, MD5_DIGEST_LEN);

    // Compare our computed hash with the sender's hash
    if (memcmp(computed, session->final_md5, MD5_DIGEST_LEN) != 0) {
        fprintf(stderr, "MD5 mismatch. Transfer corrupted.\n");
        free(file_bytes);
        return 1;  // Checksums don't match, file is corrupted
    }

    // ===== SAVE FILE TO DISK =====
    // Extract just the filename from the full path (handle both Unix and Windows paths)
    const char *base = basename_from_path(session->filename);
    char safe_name[MAX_INIT_FILENAME + 1];
    strncpy(safe_name, base ? base : "received.bin", MAX_INIT_FILENAME);
    safe_name[MAX_INIT_FILENAME] = '\0';
    if (strlen(safe_name) == 0) {
        strcpy(safe_name, "received.bin");  // Fallback if filename is empty
    }

    // Build the full directory path: output_dir/received_files
    size_t dir_len = strlen(output_dir) + 1u + strlen(RECEIVED_DIR) + 1u;
    char *dir_path = malloc(dir_len);
    if (dir_path == NULL) {
        perror("malloc");
        free(file_bytes);
        return 1;  // Memory allocation failed
    }
    snprintf(dir_path, dir_len, "%s/%s", output_dir, RECEIVED_DIR);

    // Ensure the base output directory exists (e.g., "recv_c")
    if (strcmp(output_dir, ".") != 0) {  // Skip if output_dir is "." (current directory)
#ifdef _WIN32
        if (_mkdir(output_dir) != 0 && errno != EEXIST) {
#else
        if (mkdir(output_dir, 0777) != 0 && errno != EEXIST) {
#endif
            perror("mkdir(output_dir)");
            free(dir_path);
            free(file_bytes);
            return 1;  // Failed to create directory
        }
    }

    // Ensure the received_files directory exists
#ifdef _WIN32
    if (_mkdir(dir_path) != 0 && errno != EEXIST) {
#else
    if (mkdir(dir_path, 0777) != 0 && errno != EEXIST) {
#endif
        perror("mkdir");
        free(dir_path);
        free(file_bytes);
        return 1;  // Failed to create directory
    }

    // Build the full file path: output_dir/received_files/filename
    size_t out_len = strlen(dir_path) + 1u + strlen(safe_name) + 1u;
    char *path = malloc(out_len);
    if (path == NULL) {
        perror("malloc");
        free(dir_path);
        free(file_bytes);
        return 1;  // Memory allocation failed
    }
    snprintf(path, out_len, "%s/%s", dir_path, safe_name);

    // ===== HANDLE FILENAME COLLISIONS =====
    // If a file with this name already exists, add a timestamp prefix to avoid overwriting
    FILE *existing = fopen(path, "rb");
    if (existing != NULL) {
        fclose(existing);  // File exists, close the handle
        
        // Create a unique name by prepending the current timestamp
        char unique_name[MAX_INIT_FILENAME + 32];
        snprintf(unique_name, sizeof(unique_name), "%ld_%s", (long)time(NULL), safe_name);
        
        // Build the full unique path
        size_t unique_len = strlen(dir_path) + 1u + strlen(unique_name) + 1u;
        char *unique_path = malloc(unique_len);
        if (unique_path == NULL) {
            perror("malloc");
            free(path);
            free(dir_path);
            free(file_bytes);
            return 1;  // Memory allocation failed
        }
        snprintf(unique_path, unique_len, "%s/%s", dir_path, unique_name);
        free(path);
        path = unique_path;  // Use the unique path instead
    }

    // ===== WRITE FILE TO DISK =====
    FILE *out = fopen(path, "wb");
    if (!out) {
        perror("fopen");
        free(path);
        free(dir_path);
        free(file_bytes);
        return 1;  // Failed to open file for writing
    }

    // Write all the file data
    if (fwrite(file_bytes, 1u, (size_t)total, out) != (size_t)total) {
        perror("fwrite");
        fclose(out);
        free(path);
        free(dir_path);
        free(file_bytes);
        return 1;  // Write failed
    }

    // Close the file
    fclose(out);
    
    // ===== PRINT SUCCESS STATISTICS =====
    printf("Transfer complete: %s\n", path);
    printf("File size: %llu bytes\n", (unsigned long long)total);
    printf("Packets received: %u (+ 1 init + 1 final)\n", session->max_seq);
    printf("Elapsed time: %.3f seconds\n", elapsed_sec);
    printf("Transfer rate: %.2f bytes/sec\n", total / (elapsed_sec > 0.001 ? elapsed_sec : 1));
    
    // Clean up
    free(path);
    free(dir_path);
    free(file_bytes);
    return 0;  // Success!
}

// ========== MAIN RECEIVER LOOP ==========
int main(int argc, char **argv) {
    printf("UDP File Receiver starting...\n");

    // ===== PARSE COMMAND-LINE ARGUMENTS =====
    // Usage: udp_rx <listen_port> [output_dir] [idle_timeout_ms] [loop]
    // A trailing "loop" (or -l/--loop) keeps the receiver running for multiple
    // transfers instead of exiting after one (Ctrl+C to stop).
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
        return 1;  // Incorrect usage
    }

    // Extract command-line parameters
    int listen_port = atoi(argv[1]);  // Port to listen on (required)
    const char *output_dir = argc >= 3 ? argv[2] : ".";  // Directory for received files (default: current dir)
    int idle_timeout_ms = argc >= 4 ? atoi(argv[3]) : 3000;  // Timeout in milliseconds (default: 3000ms)

    // Print the configuration
    printf("Listening on port: %d\n", listen_port);
    printf("Output scope: %s/%s\n", output_dir, RECEIVED_DIR);
    printf("Idle timeout: %d ms\n", idle_timeout_ms);

    // ===== WHY WE NEED A TIMEOUT =====
    // UDP has NO built-in delivery guarantee:
    //  - Packets can be lost in transit
    //  - No automatic retransmission
    //  - No acknowledgments
    // So if the sender stops (or a packet is dropped), we'd wait forever for a chunk that never comes
    // The timeout lets us abort incomplete transfers after a period of silence

    // ===== WINDOWS-SPECIFIC SETUP =====
#ifdef _WIN32
    // Initialize the Windows Socket API before using any socket functions
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;  // Failed to initialize Winsock
    }
#endif

    // ===== CREATE UDP SOCKET =====
    // AF_INET6 with IPV6_V6ONLY=0 gives a dual-stack socket that accepts
    // both IPv4 (127.0.0.1) and IPv6 (::1) packets on the same port.
    // This means "localhost" works regardless of whether Go resolves it to
    // IPv4 or IPv6.
    socket_t sock = socket(AF_INET6, SOCK_DGRAM, 0);

    // Check if socket creation succeeded
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
#else
    if (sock < 0) {
#endif
        perror("socket");  // Print system error message
#ifdef _WIN32
        WSACleanup();  // Clean up Winsock on Windows
#endif
        return 1;  // Failed to create socket
    }

    // Disable IPV6_V6ONLY so IPv4 packets are also received (dual-stack)
    int v6only = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));

    // ===== DISABLE WINDOWS SIO_UDP_CONNRESET =====
    // Now that we send control packets back to the sender, an ICMP "port
    // unreachable" (e.g. a control packet sent a moment before the peer is ready)
    // would otherwise make every subsequent recvfrom() fail with WSAECONNRESET
    // (10054) and spin forever. Disabling this behaviour makes recvfrom() ignore
    // such ICMP errors and keep waiting normally.
#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
    BOOL new_behavior = FALSE;
    DWORD bytes_returned = 0;
    WSAIoctl(sock, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior),
             NULL, 0, &bytes_returned, NULL, NULL);
#endif

    // ===== BIND SOCKET TO PORT =====
    // This tells the OS: "Listen for incoming packets on this port"
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));  // Clear the struct
    addr.sin6_family = AF_INET6;     // IPv6 (dual-stack)
    addr.sin6_addr = in6addr_any;    // Listen on all interfaces (:: = IPv4 + IPv6)
    addr.sin6_port = htons((uint16_t)listen_port);

    if (bind(sock, (struct sockaddr *)&addr, (int)sizeof(addr)) != 0) {
        perror("bind");  // Print system error message
        socket_close(sock);  // Close socket
#ifdef _WIN32
        WSACleanup();  // Clean up Winsock on Windows
#endif
        return 1;  // Failed to bind
    }

    // ===== SET SOCKET TIMEOUT =====
    // We use a SHORT socket timeout (CTRL_RECV_TIMEOUT_MS) so the loop wakes up
    // regularly to (re)send NAKs for whatever is still missing. The longer
    // idle_timeout_ms is used as an overall "no progress" deadline: if the sender
    // goes completely silent for that long, we give up (graceful fallback).

#ifdef _WIN32
    // Windows version: timeout is in milliseconds as a DWORD
    DWORD timeout = (DWORD)CTRL_RECV_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
#else
    // Unix/Linux version: timeout is a timeval struct (seconds + microseconds)
    struct timeval timeout;
    timeout.tv_sec = CTRL_RECV_TIMEOUT_MS / 1000;  // Whole seconds
    timeout.tv_usec = (CTRL_RECV_TIMEOUT_MS % 1000) * 1000;  // Remainder as microseconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif

    // ===== RECEIVE LOOP =====
    // Keep receiving packets until:
    //   1. All data arrives + final packet (success), or
    //   2. Timeout expires (incomplete transfer), or
    //   3. An error occurs
    unsigned char buffer[MAX_PACKET_SIZE];  // Buffer to hold incoming packets
    struct sockaddr_in6 from;  // Will hold sender's address (IPv4 or IPv6)
#ifdef _WIN32
    int from_len = (int)sizeof(from);
#else
    socklen_t from_len = (socklen_t)sizeof(from);
#endif
    // ===== OUTER LOOP: one full transfer per iteration =====
    // In loop mode we reset and keep listening after each transfer; otherwise once.
    do {
        // Fresh session state for this transfer
        Session session;
        memset(&session, 0, sizeof(session));
        session.trans_id = 0u;

        double start_time = now_seconds();      // reset to the init time once a transfer begins
        double last_progress = now_seconds();   // last received packet (for the deadline)
        double overall_deadline_sec = (double)idle_timeout_ms / 1000.0;

    while (1) {
        // Reset from_len for this iteration (some systems require this)
#ifdef _WIN32
        from_len = (int)sizeof(from);
#else
        from_len = (socklen_t)sizeof(from);
#endif

        // Wait for a UDP packet to arrive
        // recvfrom() blocks until data arrives or timeout expires
        int received = recvfrom(sock, (char *)buffer, (int)sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);

        if (received > 0) {
            // ===== PACKET RECEIVED! =====
            last_progress = now_seconds();  // Sender is alive, reset the deadline

            // Process the packet (returns 0 = ok, -1 = error, ignores bad packets)
            if (handle_packet(&session, buffer, (size_t)received) != 0) {
                fprintf(stderr, "Receiver error while handling packet\n");
                break;  // Error occurred, exit loop
            }

            // Remember where to send control replies (the sender of the init packet)
            if (session.have_init && !session.have_sender) {
                session.sender = from;
                session.sender_len = (int)from_len;
                session.have_sender = 1;
                start_time = now_seconds();  // begin timing the actual transfer
            }

            // ===== SEND A CUMULATIVE ACK =====
            // Advance our contiguous-received point and ACK it. The very first ACK
            // (sent on the init packet) doubles as "I support windowing"; a windowed
            // sender uses these to slide its window. A non-windowed sender simply
            // ignores them, so this is safe for every peer.
            if (session.have_init && session.have_sender) {
                advance_ack_base(&session);
                send_ack(sock, &session);
            }

            // ===== ARE WE DONE? =====
            // Need init + final + every data chunk to assemble and verify the file.
            if (session.have_init && session.have_final && all_chunks_present(&session)) {
                double elapsed = now_seconds() - start_time;  // Calculate elapsed time
                if (finish_transfer(&session, output_dir, elapsed) != 0) {
                    break;  // Error during finalization (e.g. MD5 mismatch)
                }
                // Tell the sender it can stop (best-effort; sent a couple of times in
                // case the COMPLETE is itself lost).
                send_control(sock, &session, (uint8_t)CTRL_COMPLETE);
                send_control(sock, &session, (uint8_t)CTRL_COMPLETE);
                break;  // Transfer done, exit loop
            }

            // ===== ANSWER THE FINAL "ARE YOU DONE?" PROBE WITH A NAK =====
            // The sender (re)sends the final packet to ask whether we have everything.
            // If we don't, answer immediately with a NAK listing the gaps. We trigger
            // only on the FINAL packet (seq == max_seq+1), never on data packets, so
            // there is no NAK storm. This drives repair without depending on our own
            // idle timeout, which the sender's periodic finals would otherwise keep
            // resetting (a livelock).
            if (session.have_sender && (size_t)received >= sizeof(DataHeader)) {
                uint32_t rseq = (uint32_t)buffer[2] << 24 | (uint32_t)buffer[3] << 16 |
                                (uint32_t)buffer[4] << 8 | (uint32_t)buffer[5];
                if (session.have_final && rseq == session.max_seq + 1u) {
                    send_control(sock, &session, (uint8_t)CTRL_NAK);
                }
            }
        } else {
            // ===== RECEIVE TIMED OUT (no packet within CTRL_RECV_TIMEOUT_MS) =====
#ifdef _WIN32
            int error_code = WSAGetLastError();
            // Check for timeout (expected) vs other errors (unexpected)
            if (error_code != WSAETIMEDOUT && error_code != WSAEWOULDBLOCK) {
                fprintf(stderr, "recvfrom failed with WSA error %d\n", error_code);
            }
#endif
            // Drive repair: periodically (re)NAK whatever is still missing so the
            // sender retransmits it. This also re-requests a lost final packet.
            if (session.have_init && session.have_sender) {
                send_control(sock, &session, (uint8_t)CTRL_NAK);
            }

            // Overall deadline measured from the last received packet. If the sender
            // is silent for longer than idle_timeout_ms, end this transfer attempt.
            if (now_seconds() - last_progress > overall_deadline_sec) {
                if (session.have_init && session.have_final && all_chunks_present(&session)) {
                    // We have everything; assemble, verify, and confirm.
                    double elapsed = now_seconds() - start_time;
                    if (finish_transfer(&session, output_dir, elapsed) == 0) {
                        send_control(sock, &session, (uint8_t)CTRL_COMPLETE);
                    }
                    break;
                }
                if (session.have_init) {
                    // A transfer started but stalled (sender went silent mid-transfer).
                    fprintf(stderr, "Transfer timed out before completion.\n");
                    break;
                }
                // No transfer in progress yet.
                if (loop_mode) {
                    last_progress = now_seconds();  // stay up and keep waiting for a sender
                    continue;
                }
                fprintf(stderr, "No packets received.\n");
                break;
            }
        }
    }

        // ===== END OF ONE TRANSFER ATTEMPT =====
        free_session(&session);  // Free this transfer's memory
        if (loop_mode) {
            printf("\n--- Ready for the next transfer on port %d (Ctrl+C to stop) ---\n", listen_port);
            fflush(stdout);  // show progress promptly even when output is redirected
        }
    } while (loop_mode);

    // ===== CLEANUP =====
    socket_close(sock);  // Close the socket
#ifdef _WIN32
    WSACleanup();  // Clean up Winsock on Windows
#endif
    return 0;  // Program exits
}
