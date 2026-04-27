// ===== IMPORTS =====
// File I/O for reading the source file
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * UDP File Sender - Fire-and-Forget Protocol
 * 
 * This sender reads a file and transmits it via UDP using a custom protocol.
 * Key protocol features:
 *   - Sequence 0: Init packet with file metadata (name, total packets)
 *   - Sequences 1..N: Data packets with file chunks (up to 1400 bytes each)
 *   - Sequence N+1: Final packet with MD5 hash for integrity verification
 * 
 * The protocol features:
 *   - No retransmission (fire-and-forget UDP)
 *   - Packet pacing to prevent buffer overflow
 *   - MD5 hashing as we send (don't read file twice)
 *   - Cross-platform byte order (Big-Endian/network byte order)
 * 
 * Payload size strategy:
 *   - Maximum payload: 1400 bytes
 *   - Rationale: Standard MTU is 1500 bytes
 *   - This leaves ~80-100 bytes for IP/UDP headers and safety margin
 *   - Reduces risk of packet fragmentation by routers
 * 
 * Usage: java UdpFileSender <dest_ip> <dest_port> <source_file> <tx_id> [pace_ms]
 */
public final class UdpFileSender {
    // ===== PROTOCOL PACKET SIZES =====
    // Data packet header: 2-byte trans_id + 4-byte seq
    private static final int HEADER_DATA_BYTES = 6;
    
    // Final packet: 2-byte trans_id + 4-byte seq (maxSeq+1) + 16-byte MD5
    private static final int FINAL_PACKET_BYTES = 22;
    
    // Default rate limiting delay between packets (milliseconds)
    // Prevents kernel socket buffer overflow
    private static final int RATE_LIMIT_MS = 1;
    
    // Maximum payload in a single data packet
    // Chosen to fit within standard MTU (1500) minus headers (~80 bytes for IP/UDP)
    // Reduces risk of the OS or routers fragmenting the packets
    private static final int MAX_DATA_PAYLOAD = 1400;
    
    // Filename length constraints
    private static final int MIN_INIT_FILENAME = 8;
    private static final int MAX_INIT_FILENAME = 2048;

    /**
     * Inner class to wrap Java's MessageDigest for MD5 hashing.
     * Provides a simplified interface for updating the hash and getting the digest.
     */
    private static final class Md5State {
        private final MessageDigest digest;

        /**
         * Initialize a new MD5 hasher.
         */
        Md5State() throws NoSuchAlgorithmException {
            this.digest = MessageDigest.getInstance("MD5");
        }

        /**
         * Add data to the MD5 hash (can be called multiple times).
         */
        void update(byte[] data, int length) {
            digest.update(data, 0, length);
        }

        /**
         * Finalize and return the 16-byte MD5 digest.
         */
        byte[] finish() {
            return digest.digest();
        }
    }

    /**
     * Main sender loop - reads file and transmits via UDP.
     * 
     * Arguments:
     *   args[0] = destination IP address (required)
     *   args[1] = destination UDP port (required)
     *   args[2] = source file path (required)
     *   args[3] = transaction ID (required)
     *   args[4] = packet pacing in ms (optional, defaults to 1ms)
     */
    public static void main(String[] args) throws Exception {
        // ===== VALIDATE COMMAND-LINE ARGUMENTS =====
        if (args.length < 4 || args.length > 5) {
            System.err.println("Usage: java UdpFileSender <dest_ip> <dest_port> <source_file> <tx_id> [pace_ms]");
            System.exit(1);
        }

        // ===== PARSE ARGUMENTS =====
        InetAddress destinationAddress = InetAddress.getByName(args[0]);  // Parse IP address
        int destinationPort = Integer.parseInt(args[1]);  // Parse port number
        String sourceFile = args[2];  // Source file path
        int transId = Integer.parseInt(args[3]) & 0xffff;  // Parse transaction ID, mask to 16 bits
        int paceMs = args.length == 5 ? Integer.parseInt(args[4]) : RATE_LIMIT_MS;  // Packet pacing
        
        // ===== VALIDATE PACING =====
        if (paceMs < 0) {
            throw new IllegalArgumentException("pace_ms must be >= 0");
        }

        // ===== PREPARE FILENAME FOR TRANSMISSION =====
        // Extract just the filename (not the full path) to send to the receiver
        String fileNameOnly = Paths.get(sourceFile).getFileName().toString();
        byte[] filenameBytes = fileNameOnly.getBytes(StandardCharsets.UTF_8);  // Encode as UTF-8
        
        // ===== VALIDATE FILENAME LENGTH =====
        // Filename must be between 8 and 2048 bytes after encoding
        if (filenameBytes.length < MIN_INIT_FILENAME || filenameBytes.length > MAX_INIT_FILENAME) {
            throw new IllegalArgumentException("Filename length must be between 8 and 2048 bytes");
        }

        // ===== SET UP DESTINATION ADDRESS =====
        InetSocketAddress remote = new InetSocketAddress(destinationAddress, destinationPort);
        long transferStart = System.currentTimeMillis();  // Record start time for throughput calculation
        long sentBytesWithHeaders = 0L;  // Track total bytes sent (including headers)

        // ===== PRINT TRANSFER CONFIGURATION =====
        System.out.println("Starting UDP transfer");
        System.out.printf("Destination: %s:%d%n", destinationAddress.getHostAddress(), destinationPort);
        System.out.printf("File: %s (%d bytes)%n", fileNameOnly, Paths.get(sourceFile).toFile().length());
        System.out.printf("Transaction ID: %d%n", transId);
        System.out.printf("Packet pacing: %d ms%n", paceMs);

        // ===== OPEN UDP SOCKET =====
        try (DatagramChannel channel = DatagramChannel.open()) {
            channel.configureBlocking(true);  // Blocking mode (wait for sends to complete)

            // ===== OPEN AND READ SOURCE FILE =====
            try (RandomAccessFile file = new RandomAccessFile(sourceFile, "r")) {
                long fileSize = file.length();  // Get total file size
                
                // ===== CALCULATE PACKET COUNT =====
                // Divide file size by max payload, rounding up
                // This is how many data packets we'll need to send
                long maxSeq = (fileSize + MAX_DATA_PAYLOAD - 1L) / MAX_DATA_PAYLOAD;
                
                // ===== BUILD AND SEND INIT PACKET =====
                // The init packet tells the receiver:
                //   - The transaction ID (to identify this transfer)
                //   - The filename (so receiver knows what to save as)
                //   - How many data packets to expect (maxSeq)
                
                // Build packet with Big-Endian byte order for network compatibility
                // Cross-platform requirement:
                //   - C sender uses htonl() to convert to Big-Endian
                //   - Java defaults to little-endian on x86
                //   - If we don't set BIG_ENDIAN, the C receiver would read garbage data
                byte[] initPacket = ByteBuffer.allocate(10 + filenameBytes.length)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putShort((short) transId)  // Transaction ID (2 bytes)
                        .putInt(0)  // Sequence number = 0 (indicates this is init packet)
                        .putInt((int) maxSeq)  // Maximum sequence number (how many data packets)
                        .put(filenameBytes)  // Append filename bytes
                        .array();
                
                // Send the init packet
                channel.send(ByteBuffer.wrap(initPacket), remote);
                sentBytesWithHeaders += initPacket.length;
                System.out.printf("Data packets: %d%n", maxSeq);

                // ===== INITIALIZE MD5 HASHER =====
                // We compute the MD5 hash as we send, to avoid reading file twice
                Md5State md5 = new Md5State();
                
                // ===== PREPARE DATA PACKET BUFFERS =====
                byte[] buffer = new byte[MAX_DATA_PAYLOAD];  // Buffer for reading file chunks
                byte[] dataPacket = new byte[HEADER_DATA_BYTES + MAX_DATA_PAYLOAD];  // Full packet buffer
                
                // Create a ByteBuffer view for the header (first 6 bytes)
                ByteBuffer header = ByteBuffer.wrap(dataPacket).order(ByteOrder.BIG_ENDIAN);
                header.putShort((short) transId);  // Write transaction ID to header

                // ===== CORE FIRE-AND-FORGET SEND LOOP =====
                // UDP has NO delivery guarantee + NO ACKs + NO retransmission
                // We just send packets sequentially and hope they arrive
                // The receiver will detect missing chunks via timeout
                for (long seq = 1; seq <= maxSeq; ++seq) {
                    // ===== READ CHUNK FROM FILE =====
                    int read = file.read(buffer);  // Read up to MAX_DATA_PAYLOAD bytes
                    if (read < 0) {
                        read = 0;  // Handle EOF (shouldn't happen if file size is correct)
                    }
                    
                    // ===== UPDATE MD5 HASH DYNAMICALLY =====
                    // Hash the file as we read/send it (don't read file twice for efficiency)
                    md5.update(buffer, read);
                    
                    // ===== BUILD DATA PACKET =====
                    // Update the sequence number in the packet header
                    header.position(2);  // Skip to seq field (after trans_id)
                    header.putInt((int) seq);  // Write sequence number
                    // Copy file data to packet (after the 6-byte header)
                    System.arraycopy(buffer, 0, dataPacket, HEADER_DATA_BYTES, read);
                    
                    // ===== SEND DATA PACKET =====
                    channel.send(ByteBuffer.wrap(dataPacket, 0, HEADER_DATA_BYTES + read), remote);
                    sentBytesWithHeaders += HEADER_DATA_BYTES + read;

                    // ===== RATE LIMITING =====
                    // UDP has no backpressure mechanisms, so without rate-limiting,
                    // blasting packets in a tight loop would overflow the kernel socket buffer
                    // By limiting to ~1000 packets/sec (1ms delay), we stay within safe limits
                    if (!pauseBetweenPackets(paceMs)) {
                        break;  // If interrupted, stop sending
                    }
                }

                // ===== BUILD AND SEND FINAL PACKET =====
                // The final packet contains:
                //   - trans_id: same transaction ID as all other packets
                //   - seq: maxSeq+1 (one past the last data packet) to indicate this is the final packet
                //   - md5: the 16-byte MD5 hash of the entire file
                
                // This packet allows the receiver to:
                //   1. Know the transfer is complete
                //   2. Verify integrity (if computed MD5 matches, nothing was lost/corrupted)
                byte[] digest = md5.finish();  // Finalize MD5 hash
                ByteBuffer finalPacket = ByteBuffer.allocate(FINAL_PACKET_BYTES)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putShort((short) transId)  // Transaction ID
                        .putInt((int) (maxSeq + 1))  // Special sequence number (indicates final packet)
                        .put(digest);  // Append 16-byte MD5 hash
                channel.send((ByteBuffer) finalPacket.flip(), remote);
                sentBytesWithHeaders += FINAL_PACKET_BYTES;

                // ===== PRINT TRANSFER COMPLETION SUMMARY =====
                long elapsedMs = System.currentTimeMillis() - transferStart;
                double elapsedSec = Math.max(0.001, elapsedMs / 1000.0);  // Avoid division by zero
                System.out.println("Transfer sent. File MD5: " + toHex(digest));
                System.out.printf("Bytes sent (including protocol headers): %d%n", sentBytesWithHeaders);
                System.out.printf("Elapsed time: %.3f seconds%n", elapsedSec);
                System.out.printf("Average throughput: %.2f bytes/sec%n", fileSize / elapsedSec);
            }
        }
    }

    /**
     * Convert a byte array to its hexadecimal string representation.
     * Used for displaying MD5 hashes in human-readable format.
     */
    private static String toHex(byte[] bytes) {
        // ===== BUILD HEX STRING =====
        // Each byte becomes 2 hex characters (00-FF)
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            // Format each byte as 2-digit hex with leading zero if needed
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    /**
     * Rate-limit between packet sends to prevent buffer overflow.
     * Sleeps for the specified milliseconds.
     * Returns false if interrupted, true otherwise.
     */
    private static boolean pauseBetweenPackets(int paceMs) {
        // ===== RATE LIMIT DELAY =====
        try {
            if (paceMs > 0) {
                // Sleep for paceMs milliseconds to throttle the send rate
                Thread.sleep(paceMs);
            }
            return true;  // Completed successfully
        } catch (InterruptedException e) {
            // Thread was interrupted (e.g., by Ctrl+C)
            Thread.currentThread().interrupt();  // Restore interrupt status
            System.err.println("Sender was interrupted.");
            return false;  // Signal to stop sending
        }
    }
}