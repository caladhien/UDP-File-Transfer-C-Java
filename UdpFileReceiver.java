// ===== IMPORTS =====
// Java I/O and file operations
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * UDP File Receiver - Fire-and-Forget Protocol
 * 
 * This receiver listens on a UDP port and reassembles files sent via a custom protocol.
 * Key protocol features:
 *   - Sequence 0: Init packet with file metadata (name, total packets)
 *   - Sequences 1..N: Data packets with file chunks (up to 1400 bytes each)
 *   - Sequence N+1: Final packet with MD5 hash for integrity verification
 * 
 * The protocol handles:
 *   - Out-of-order delivery (stores chunks by sequence number)
 *   - Missing packets (timeout-based detection)
 *   - Data integrity (MD5 verification)
 *   - Cross-platform byte order (Big-Endian/network byte order)
 * 
 * Usage: java UdpFileReceiver <listen_port> [output_dir] [idle_timeout_ms]
 */
public final class UdpFileReceiver {
    // ===== PROTOCOL PACKET SIZES =====
    // These are fixed by the protocol schema (same on sender side)
    
    // Init packet: 2-byte trans_id + 4-byte max_seq + 4-byte seq (always 0)
    private static final int HEADER_INIT_BYTES = 10;
    
    // Data packet header: 2-byte trans_id + 4-byte seq
    private static final int HEADER_DATA_BYTES = 6;
    
    // Final packet: header (6 bytes) + MD5 hash (16 bytes)
    private static final int FINAL_BYTES = 22;
    
    // Maximum payload in a single data packet
    // Chosen to fit within standard MTU (1500) minus headers (~80 bytes for IP/UDP)
    private static final int MAX_DATA_PAYLOAD = 1400;
    
    // Filename length constraints
    private static final int MIN_INIT_FILENAME = 8;
    private static final int MAX_INIT_FILENAME = 2048;
    
    // Default directory for saving received files
    private static final String RECEIVED_DIR = "received_files";

    /**
     * Inner class to track state of a single UDP transfer session.
     * One session = one file transfer from one sender.
     */
    private static final class Session {
        long transId = -1L;  // Transaction ID from init packet (identifies this transfer)
        long maxSeq = -1L;  // Total number of data packets to expect
        String filename;  // Filename sent in init packet
        
        // Map to store out-of-order UDP chunks by their sequence number
        // Key = sequence number, Value = chunk bytes
        // Using HashMap allows O(1) insertion regardless of arrival order
        final Map<Long, byte[]> chunks = new HashMap<>();
        
        byte[] finalMd5;  // The 16-byte MD5 hash from the final packet
        boolean initSeen;  // Flag: have we received the init packet?
        boolean finalSeen;  // Flag: have we received the final packet?

        /**
         * Check if transfer is complete (all required state and data present).
         * Returns true only when:
         *   1. Init packet has been received
         *   2. Final packet has been received
         *   3. We have received exactly maxSeq data packets (all chunks)
         */
        boolean isReadyToFinish() {
            // Transfer is complete only when all required states and chunks are present
            return initSeen && finalSeen && maxSeq >= 0 && chunks.size() == maxSeq;
        }
    }

    /**
     * Main receive loop - listens for UDP packets and reassembles the file.
     * 
     * Arguments:
     *   args[0] = listen port (required)
     *   args[1] = output directory (optional, defaults to current directory)
     *   args[2] = idle timeout in ms (optional, defaults to 3000ms)
     */
    public static void main(String[] args) throws Exception {
        // ===== VALIDATE COMMAND-LINE ARGUMENTS =====
        if (args.length < 1 || args.length > 3) {
            System.err.println("Usage: java UdpFileReceiver <listen_port> [output_dir] [idle_timeout_ms]");
            System.exit(1);
        }

        // ===== PARSE ARGUMENTS =====
        int listenPort = Integer.parseInt(args[0]);  // UDP port to listen on
        Path outputDir = Paths.get(args.length >= 2 ? args[1] : ".");  // Where to save files
        int idleTimeoutMs = args.length >= 3 ? Integer.parseInt(args[2]) : 3000;  // Timeout for detecting stalled transfers
        long transferStart = System.currentTimeMillis();  // Record start time for throughput calculation

        // ===== CREATE OUTPUT DIRECTORIES =====
        // Ensure output directory exists and create subdirectory for received files
        Files.createDirectories(outputDir);
        Path scopedReceiveDir = outputDir.resolve(RECEIVED_DIR);
        Files.createDirectories(scopedReceiveDir);

        // ===== PRINT RECEIVER CONFIGURATION =====
        System.out.println("UDP File Receiver starting...");
        System.out.printf("Listening on port: %d%n", listenPort);
        System.out.printf("Output scope: %s%n", scopedReceiveDir.toAbsolutePath());
        System.out.printf("Idle timeout: %d ms%n", idleTimeoutMs);

        // ===== INITIALIZE TRANSFER SESSION AND PACKET BUFFER =====
        Session session = new Session();  // State for the current transfer
        byte[] buffer = new byte[4096];  // Buffer to receive UDP packets
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);  // Packet object for receiving

        // ===== MAIN RECEIVE LOOP =====
        // This socket will receive all UDP packets on the specified port
        try (DatagramSocket socket = new DatagramSocket(listenPort)) {
            // Set a read timeout of 500ms so we don't block forever if no packets arrive
            socket.setSoTimeout(500);
            long lastPacketAt = System.currentTimeMillis();  // Track when we last got a packet

            while (true) {
                try {
                    // Block and wait for a UDP packet to arrive
                    socket.receive(packet);
                    lastPacketAt = System.currentTimeMillis();  // Update "last packet time"
                    
                    // Process the received packet: update session state, store chunks, etc.
                    handlePacket(session, packet.getData(), packet.getLength());
                    
                    // Check if transfer is complete (all packets arrived)
                    if (session.isReadyToFinish()) {
                        finishTransfer(session, scopedReceiveDir, transferStart);
                        return;  // Transfer done, exit
                    }
                } catch (SocketTimeoutException timeout) {
                    // ===== HANDLE IDLE TIMEOUT =====
                    // No packet arrived within 500ms (our socket timeout)
                    // This helps detect when a sender has finished or crashed
                    // Since UDP uses "fire-and-forget" (no retransmissions),
                    // if we're missing a packet, the sender won't resend it
                    
                    if (session.initSeen && System.currentTimeMillis() - lastPacketAt > idleTimeoutMs) {
                        // We've waited longer than the idle timeout after the init packet
                        if (session.isReadyToFinish()) {
                            // We have all packets - transfer is complete
                            finishTransfer(session, scopedReceiveDir, transferStart);
                        } else {
                            // Transfer incomplete - some packets were lost and sender won't retry
                            System.err.println("Transfer timed out before all packets arrived.");
                            System.err.printf("Received %d of %d data packets.%n", session.chunks.size(), session.maxSeq);
                            System.exit(2);
                        }
                        return;
                    }
                }
            }
        }
    }

    /**
     * Process a received UDP packet and update the session state.
     * 
     * Packet types:
     *   - Init (seq=0): Filename and metadata
     *   - Data (seq=1..maxSeq): File chunks
     *   - Final (seq=maxSeq+1): MD5 hash
     */
    private static void handlePacket(Session session, byte[] data, int length) throws NoSuchAlgorithmException {
        // ===== VALIDATE PACKET LENGTH =====
        if (length < HEADER_DATA_BYTES) {
            // Packet is too short to contain even the header - discard it
            return;
        }

        // ===== PARSE PACKET HEADER =====
        // Wrap the data in a ByteBuffer and force Big-Endian byte order
        // This is CRITICAL for cross-platform compatibility:
        //   - The C sender uses htonl() to convert to network byte order (Big-Endian)
        //   - Java defaults to little-endian on x86 platforms
        //   - By explicitly setting BIG_ENDIAN, we match what the C sender sent
        ByteBuffer buffer = ByteBuffer.wrap(data, 0, length).order(ByteOrder.BIG_ENDIAN);
        
        // Read the transaction ID (16-bit unsigned value)
        // Java doesn't have unsigned types, so convert to int to avoid sign issues
        int transId = Short.toUnsignedInt(buffer.getShort());
        
        // Read the sequence number (32-bit unsigned value)
        // Java doesn't have native unsigned 32-bit integers
        // We convert to 64-bit (long) to avoid overflow that would make it negative
        long seq = Integer.toUnsignedLong(buffer.getInt());

        // ===== HANDLE INIT PACKET (SEQUENCE 0) =====
        // The first valid packet MUST be init with seq=0
        if (!session.initSeen) {
            // Ignore this packet if it's not init (seq != 0) or too short
            if (seq != 0L || length < HEADER_INIT_BYTES) {
                return;
            }

            // ===== PARSE INIT PACKET =====
            // Read the maximum sequence number (how many data packets to expect)
            long maxSeq = Integer.toUnsignedLong(buffer.getInt());
            
            // Extract the filename bytes (everything after the header)
            byte[] filenameBytes = Arrays.copyOfRange(data, HEADER_INIT_BYTES, length);
            
            // Validate filename length
            if (filenameBytes.length < MIN_INIT_FILENAME || filenameBytes.length > MAX_INIT_FILENAME) {
                return;
            }

            // ===== DECODE FILENAME =====
            // Convert bytes to string using UTF-8 encoding
            String filename = new String(filenameBytes, StandardCharsets.UTF_8);

            // ===== STORE SESSION STATE =====
            // Remember this sender's transaction ID (to ignore packets from other senders)
            session.transId = Integer.toUnsignedLong(transId);
            session.maxSeq = maxSeq;
            session.filename = filename;
            session.initSeen = true;  // Mark that we've seen the init packet
            return;
        }

        // ===== IGNORE PACKETS FROM DIFFERENT TRANSACTIONS =====
        // If this packet has a different trans_id, it's from a different sender - ignore it
        if (Integer.toUnsignedLong(transId) != session.transId) {
            return;
        }

        // ===== HANDLE FINAL PACKET (SEQUENCE MAXSEQ+1) =====
        // The final packet contains the sender's MD5 hash for verification
        // Its payload is exactly 16 bytes (the MD5 digest)
        if (seq == session.maxSeq + 1L && length == FINAL_BYTES) {
            // Extract the 16-byte MD5 hash from the packet
            byte[] md5 = Arrays.copyOfRange(data, HEADER_DATA_BYTES, FINAL_BYTES);
            session.finalMd5 = md5;
            session.finalSeen = true;  // Mark that we've seen the final packet
            return;
        }

        // ===== IGNORE INVALID DATA PACKETS =====
        // Reject seq=0 (that's init) or seq > maxSeq (out of range)
        if (seq == 0L || seq > session.maxSeq) {
            return;
        }

        // ===== EXTRACT AND STORE DATA CHUNK =====
        // Calculate payload size (everything after the header)
        int payloadLength = length - HEADER_DATA_BYTES;
        
        // Validate payload size
        if (payloadLength < 0 || payloadLength > MAX_DATA_PAYLOAD) {
            return;
        }

        // ===== STORE CHUNK BY SEQUENCE NUMBER =====
        // UDP packets can arrive out of order!
        // Instead of writing immediately, we store them in a HashMap keyed by sequence number
        // This allows us to reassemble in the correct order later, regardless of arrival order
        session.chunks.putIfAbsent(seq, Arrays.copyOfRange(data, HEADER_DATA_BYTES, length));
    }

    /**
     * Assemble all received chunks into the complete file and verify integrity.
     * Called when all packets have been received.
     */
    private static void finishTransfer(Session session, Path receiveDir, long transferStart) throws IOException, NoSuchAlgorithmException {
        // ===== SANITY CHECK =====
        if (!session.isReadyToFinish()) {
            throw new IllegalStateException("Transfer is not complete.");
        }

        // ===== CALCULATE TOTAL FILE SIZE =====
        // Sum the lengths of all chunks to determine final file size
        long totalLength = 0L;
        for (long seq = 1L; seq <= session.maxSeq; ++seq) {
            byte[] chunk = session.chunks.get(seq);
            if (chunk == null) {
                throw new IllegalStateException("Missing chunk " + seq);
            }
            totalLength += chunk.length;
        }

        // ===== CHECK FOR INTEGER OVERFLOW =====
        // Ensure the file fits in Java's int-based byte array size
        if (totalLength > Integer.MAX_VALUE) {
            throw new IllegalStateException("File too large to assemble in memory.");
        }

        // ===== REASSEMBLE FILE IN ORDER =====
        // Create a single byte array for the complete file
        byte[] fileBytes = new byte[(int) totalLength];
        int offset = 0;  // Track where we are in the output buffer
        
        // Initialize MD5 hasher so we can verify integrity
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        // ===== COPY CHUNKS IN SEQUENCE ORDER =====
        // Go through sequences 1 to maxSeq in order and copy chunks into the file buffer
        // Also compute MD5 hash as we go (to match the sender's hash computation)
        // This deterministic reassembly order ensures reproducible output and hash
        for (long seq = 1L; seq <= session.maxSeq; ++seq) {
            byte[] chunk = session.chunks.get(seq);
            System.arraycopy(chunk, 0, fileBytes, offset, chunk.length);  // Copy chunk
            md5.update(chunk);  // Add to MD5 hash
            offset += chunk.length;  // Advance output buffer pointer
        }

        // ===== FINALIZE AND VERIFY MD5 =====
        // Get the computed MD5 hash (16 bytes)
        byte[] computed = md5.digest();
        
        // ===== INTEGRITY CHECK =====
        // Compare our computed MD5 with the sender's MD5
        // If they don't match, some packet was corrupted or lost in transit
        // (Fire-and-forget protocol won't retry, so we catch it here)
        if (!Arrays.equals(computed, session.finalMd5)) {
            throw new IllegalStateException("MD5 mismatch. Transfer corrupted.");
        }

        // ===== PRINT HASH VERIFICATION =====
        System.out.println("MD5 received: " + toHex(session.finalMd5));
        System.out.println("MD5 computed: " + toHex(computed));

        // ===== DETERMINE OUTPUT FILENAME =====
        // Extract just the filename (not full path) from session.filename
        Path namePath = Paths.get(session.filename).getFileName();
        String safeName = namePath == null ? "received.bin" : namePath.toString();
        if (safeName.isEmpty()) {
            safeName = "received.bin";
        }

        // ===== WRITE FILE TO DISK =====
        // Find a unique filename (avoid overwriting existing files)
        Path outputFile = uniqueOutputPath(receiveDir, safeName);
        Files.write(outputFile, fileBytes);  // Write all bytes to the file

        // ===== PRINT TRANSFER COMPLETION SUMMARY =====
        double elapsedSec = Math.max(0.001, (System.currentTimeMillis() - transferStart) / 1000.0);
        System.out.println("Transfer complete: " + outputFile);
        System.out.println("MD5 verified: " + toHex(computed));
        System.out.printf("File size: %d bytes%n", totalLength);
        System.out.printf("Packets received: %d%n", session.maxSeq);
        System.out.printf("Elapsed time: %.3f seconds%n", elapsedSec);
        System.out.printf("Transfer rate: %.2f bytes/sec%n", totalLength / elapsedSec);
    }

    /**
     * Generate a unique output path, appending a timestamp if the file already exists.
     * This prevents overwriting files that were previously received.
     */
    private static Path uniqueOutputPath(Path dir, String fileName) throws IOException {
        // ===== CHECK IF FILE EXISTS =====
        Path candidate = dir.resolve(fileName).normalize();
        if (!Files.exists(candidate)) {
            return candidate;  // File doesn't exist, we can use this name
        }

        // ===== FILE EXISTS - GENERATE UNIQUE NAME =====
        // Extract stem (filename without extension) and extension separately
        String stem = fileName;
        String ext = "";
        int dot = fileName.lastIndexOf('.');
        if (dot > 0) {
            stem = fileName.substring(0, dot);
            ext = fileName.substring(dot);
        }

        // ===== APPEND TIMESTAMP SUFFIX =====
        // Millisecond timestamp makes the name unique and sortable by time
        String suffix = "_" + System.currentTimeMillis();
        candidate = dir.resolve(stem + suffix + ext).normalize();
        
        // ===== ENSURE UNIQUENESS =====
        // In case of collisions (extremely unlikely), append an index
        int index = 1;
        while (Files.exists(candidate)) {
            candidate = dir.resolve(stem + suffix + "_" + index + ext).normalize();
            index++;
        }
        return candidate;
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
            // Format each byte as 2-digit hex with leading zero if needed
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }
}