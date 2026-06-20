// ===== IMPORTS =====
// Java I/O and file operations
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
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
    private static final int MIN_INIT_FILENAME = 1;
    private static final int MAX_INIT_FILENAME = 2048;

    // Default directory for saving received files
    private static final String RECEIVED_DIR = "received_files";

    // ===== CONTROL CHANNEL (RX -> TX) =====
    // We send these back to the sender so it can retransmit losses (NAK) or stop (COMPLETE).
    private static final int CTRL_NAK = 0;        // resend these data seqs, then resend final
    private static final int CTRL_COMPLETE = 1;   // all received and MD5 verified, you may stop
    private static final int CTRL_ACK = 2;        // cumulative ACK: everything below ack_base is in
    // Cap on missing seqs listed per NAK packet. The seq list gets the same byte budget as
    // a data packet's payload, so a NAK datagram (5 + 4*N) is the same MTU-safe size as a
    // data packet: 1400/4 = 350 seqs -> 5 + 1400 = 1405 bytes.
    private static final int MAX_NAK_SEQS = MAX_DATA_PAYLOAD / 4;
    // Short socket timeout so the loop wakes up regularly to (re)send NAKs.
    private static final int CTRL_RECV_TIMEOUT_MS = 500;

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
        SocketAddress sender;  // Where to send ACK/NAK control replies
        long ackBase = 1L;  // Lowest seq still missing (cumulative ACK point)

        /** Advance the cumulative ACK point past every contiguous chunk we now hold. */
        void advanceAckBase() {
            if (ackBase < 1L) {
                ackBase = 1L;
            }
            while (ackBase <= maxSeq && chunks.containsKey(ackBase)) {
                ackBase++;
            }
        }

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
        // A trailing "loop" (or -l/--loop) keeps the receiver running for multiple
        // transfers instead of exiting after one (Ctrl+C to stop).
        boolean loopMode = false;
        if (args.length > 0) {
            String last = args[args.length - 1];
            if (last.equalsIgnoreCase("loop") || last.equals("-l") || last.equals("--loop")) {
                loopMode = true;
                args = Arrays.copyOf(args, args.length - 1);  // hide the flag from positional parsing
            }
        }
        if (args.length < 1 || args.length > 3) {
            System.err.println("Usage: java UdpFileReceiver <listen_port> [output_dir] [idle_timeout_ms] [loop]");
            System.exit(1);
        }

        // ===== PARSE ARGUMENTS =====
        int listenPort = Integer.parseInt(args[0]);  // UDP port to listen on
        Path outputDir = Paths.get(args.length >= 2 ? args[1] : ".");  // Where to save files
        int idleTimeoutMs = args.length >= 3 ? Integer.parseInt(args[2]) : 3000;  // Timeout for detecting stalled transfers

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

        // ===== PACKET BUFFER (reused across transfers) =====
        byte[] buffer = new byte[4096];  // Buffer to receive UDP packets
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);  // Packet object for receiving

        // ===== MAIN RECEIVE LOOP =====
        // This socket will receive all UDP packets on the specified port
        try (DatagramSocket socket = new DatagramSocket(listenPort)) {
            // Short read timeout so the loop wakes regularly to (re)send NAKs. The longer
            // idleTimeoutMs is used as an overall "no progress" deadline (graceful fallback).
            socket.setSoTimeout(CTRL_RECV_TIMEOUT_MS);

            // Outer loop: one full transfer per iteration. In loop mode we reset and keep
            // listening after each transfer; otherwise we run exactly once.
            do {
                Session session = new Session();  // Fresh state for this transfer
                long transferStart = System.currentTimeMillis();  // reset to init time once a transfer begins
                long lastPacketAt = System.currentTimeMillis();  // Track when we last got a packet

                while (true) {
                try {
                    // Block and wait for a UDP packet to arrive
                    socket.receive(packet);
                    lastPacketAt = System.currentTimeMillis();  // Sender is alive, reset deadline

                    // Process the received packet: update session state, store chunks, etc.
                    handlePacket(session, packet.getData(), packet.getLength());

                    // Remember where to send control replies (the sender of the init packet)
                    if (session.initSeen && session.sender == null) {
                        session.sender = packet.getSocketAddress();
                        transferStart = System.currentTimeMillis();  // begin timing the actual transfer
                    }

                    // ===== SEND A CUMULATIVE ACK =====
                    // The first ACK (on init) advertises windowing support; a windowed
                    // sender uses these to slide its window. Others simply ignore them.
                    if (session.initSeen && session.sender != null) {
                        session.advanceAckBase();
                        sendAck(socket, session);
                    }

                    // ===== ARE WE DONE? (init + final + every data chunk) =====
                    if (session.isReadyToFinish()) {
                        finishTransfer(session, scopedReceiveDir, transferStart);
                        // Tell the sender it can stop (sent twice in case a COMPLETE is lost)
                        sendControl(socket, session, CTRL_COMPLETE);
                        sendControl(socket, session, CTRL_COMPLETE);
                        break;  // Transfer done; outer loop resets (or exits) below
                    }

                    // ===== ANSWER THE FINAL "ARE YOU DONE?" PROBE WITH A NAK =====
                    // The sender (re)sends the final packet to ask whether we have
                    // everything. If we don't, answer immediately with a NAK listing the
                    // gaps. We trigger only on the FINAL packet (seq == maxSeq+1), never on
                    // data packets, so there is no NAK storm. This drives repair without
                    // relying on our idle timeout, which the sender's periodic finals would
                    // otherwise keep resetting (a livelock).
                    if (session.sender != null && packet.getLength() >= HEADER_DATA_BYTES) {
                        long seq = Integer.toUnsignedLong(
                                ByteBuffer.wrap(packet.getData(), 0, packet.getLength())
                                        .order(ByteOrder.BIG_ENDIAN).getInt(2));
                        if (session.finalSeen && seq == session.maxSeq + 1L) {
                            sendControl(socket, session, CTRL_NAK);
                        }
                    }
                } catch (SocketTimeoutException timeout) {
                    // ===== NO PACKET WITHIN CTRL_RECV_TIMEOUT_MS =====
                    if (!session.initSeen) {
                        continue;  // Nothing started yet; keep waiting
                    }

                    // Drive repair: periodically (re)NAK whatever is still missing so the
                    // sender retransmits it (an empty NAK also re-requests a lost final packet).
                    if (session.sender != null) {
                        sendControl(socket, session, CTRL_NAK);
                    }

                    // Overall deadline: if the sender has been silent too long, fall back to
                    // the legacy behaviour (save if complete, else report and exit non-zero).
                    if (System.currentTimeMillis() - lastPacketAt > idleTimeoutMs) {
                        if (session.isReadyToFinish()) {
                            finishTransfer(session, scopedReceiveDir, transferStart);
                            sendControl(socket, session, CTRL_COMPLETE);
                        } else {
                            System.err.println("Transfer timed out before all packets arrived.");
                            System.err.printf("Received %d of %d data packets.%n", session.chunks.size(), session.maxSeq);
                            if (!loopMode) {
                                System.exit(2);  // one-shot mode: signal incomplete transfer
                            }
                        }
                        break;  // End this transfer attempt
                    }
                }
            }

            if (loopMode) {
                System.out.printf("%n--- Ready for the next transfer on port %d (Ctrl+C to stop) ---%n", listenPort);
            }
        } while (loopMode);
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
     * Send a control packet back to the sender.
     *   CTRL_COMPLETE -> empty body, tells the sender to stop.
     *   CTRL_NAK      -> lists up to MAX_NAK_SEQS missing data seqs (count==0 means
     *                    "I have all data, just resend the final/MD5 packet").
     * Matches the ControlHeader wire format used by the sender.
     */
    private static void sendControl(DatagramSocket socket, Session session, int type) throws IOException {
        if (session.sender == null) {
            return;  // We don't know where to reply yet
        }

        byte[] buf;
        if (type == CTRL_NAK) {
            // Collect the missing data sequence numbers (capped to one datagram)
            List<Long> missing = new ArrayList<>();
            for (long seq = 1; seq <= session.maxSeq && missing.size() < MAX_NAK_SEQS; ++seq) {
                if (!session.chunks.containsKey(seq)) {
                    missing.add(seq);
                }
            }
            buf = new byte[5 + 4 * missing.size()];
            ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN);
            bb.putShort((short) session.transId);
            bb.put((byte) CTRL_NAK);
            bb.putShort((short) missing.size());
            for (long seq : missing) {
                bb.putInt((int) seq);
            }
        } else {
            buf = new byte[5];
            ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN);
            bb.putShort((short) session.transId);
            bb.put((byte) CTRL_COMPLETE);
            bb.putShort((short) 0);
        }

        socket.send(new DatagramPacket(buf, buf.length, session.sender));
    }

    /**
     * Send a cumulative ACK back to the sender. Wire layout:
     *   trans_id(2) | type=CTRL_ACK | count(2)=0 | ack_base(4)   (9 bytes)
     * The first ACK (on the init packet) advertises "I support windowing"; a windowed
     * sender uses these to slide its window. Non-windowed senders ignore them.
     */
    private static void sendAck(DatagramSocket socket, Session session) throws IOException {
        if (session.sender == null) {
            return;
        }
        byte[] buf = ByteBuffer.allocate(9).order(ByteOrder.BIG_ENDIAN)
                .putShort((short) session.transId)
                .put((byte) CTRL_ACK)
                .putShort((short) 0)            // no SACK blocks
                .putInt((int) session.ackBase)  // cumulative ACK point
                .array();
        socket.send(new DatagramPacket(buf, buf.length, session.sender));
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