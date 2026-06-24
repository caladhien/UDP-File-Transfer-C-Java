// ===== IMPORTS =====
// File I/O for reading the source file
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
    private static final int MIN_INIT_FILENAME = 1;
    private static final int MAX_INIT_FILENAME = 2048;

    // ===== CONTROL CHANNEL (RX -> TX) =====
    // The receiver replies with these so we can repair losses (NAK) or stop (COMPLETE).
    private static final int CTRL_NAK = 0;        // resend listed seqs, then resend final
    private static final int CTRL_COMPLETE = 1;   // all received and verified, stop
    private static final int CTRL_ACK = 2;        // cumulative ACK: receiver has everything below ack_base

    // ===== SLIDING WINDOW (optional fast path) =====
    // If the receiver advertises ACK support (an ACK right after init), we switch
    // from "blast then repair" to a Selective-Repeat sliding window.
    private static final int WINDOW_SIZE = 64;          // max data packets in flight
    private static final int RTO_MS = 100;              // retransmit timeout (ms) for the oldest unacked
    private static final int WIN_RECV_TIMEOUT_MS = 20;  // how long we block for an ACK each turn
    private static final int PROBE_TRIES = 5;           // init re-sends while probing for ACK support
    private static final int PROBE_WAIT_MS = 150;       // wait per probe attempt
    private static final long WIN_STALL_ABORT_MS = 30_000L;  // give up if the window makes no progress
    // Cap on missing seqs per NAK packet. The seq list gets the same byte budget as a
    // data packet's payload, so a NAK datagram (5 + 4*N) is the same MTU-safe size as a
    // data packet: 1400/4 = 350 seqs -> 5 + 1400 = 1405 bytes.
    private static final int MAX_NAK_SEQS = MAX_DATA_PAYLOAD / 4;
    private static final int CTRL_RECV_TIMEOUT_MS = 500;  // how long to wait for a control packet
    // Max consecutive idle timeouts before assuming a fire-and-forget receiver and
    // exiting (each control reply refills this). 10 * 500ms = 5s of silence.
    private static final int MAX_RETRIES = 10;

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
        // Filename must be between MIN_INIT_FILENAME and MAX_INIT_FILENAME bytes after encoding
        if (filenameBytes.length < MIN_INIT_FILENAME || filenameBytes.length > MAX_INIT_FILENAME) {
            throw new IllegalArgumentException(
                    "Filename length must be between " + MIN_INIT_FILENAME + " and " + MAX_INIT_FILENAME + " bytes");
        }

        // ===== SET UP DESTINATION ADDRESS =====
        long transferStart = System.currentTimeMillis();  // Record start time for throughput calculation
        long sentBytesWithHeaders = 0L;  // Track total bytes sent (including headers)

        // ===== TEST KNOB: SIMULATE PACKET LOSS =====
        // Set DROP_PCT (0-100) to randomly skip sending some data packets on the FIRST
        // pass only. Retransmits are never dropped, so the receiver's NAKs let the transfer
        // converge. Used to prove the ACK/NAK repair loop works. Defaults to 0 (no loss).
        int dropPct = 0;
        String dropEnv = System.getenv("DROP_PCT");
        if (dropEnv != null) {
            try {
                dropPct = Math.max(0, Math.min(100, Integer.parseInt(dropEnv.trim())));
            } catch (NumberFormatException ignored) {
                dropPct = 0;
            }
        }
        java.util.Random rng = new java.util.Random();
        long droppedCount = 0L;

        // ===== PRINT TRANSFER CONFIGURATION =====
        System.out.println("Starting UDP transfer");
        System.out.printf("Destination: %s:%d%n", destinationAddress.getHostAddress(), destinationPort);
        System.out.printf("File: %s (%d bytes)%n", fileNameOnly, Paths.get(sourceFile).toFile().length());
        System.out.printf("Transaction ID: %d%n", transId);
        System.out.printf("Packet pacing: %d ms%n", paceMs);

        // ===== OPEN UDP SOCKET =====
        // A DatagramSocket (rather than a channel) lets us both send and, in the control
        // phase, block on receive() with a timeout to collect ACK/NAK replies.
        try (DatagramSocket socket = new DatagramSocket()) {

            // ===== OPEN AND READ SOURCE FILE =====
            try (RandomAccessFile file = new RandomAccessFile(sourceFile, "r")) {
                long fileSize = file.length();  // Get total file size

                // ===== CALCULATE PACKET COUNT =====
                // Divide file size by max payload, rounding up
                // This is how many data packets we'll need to send
                long maxSeq = (fileSize + MAX_DATA_PAYLOAD - 1L) / MAX_DATA_PAYLOAD;

                // ===== BUILD AND SEND INIT PACKET =====
                // Build packet with Big-Endian byte order for network compatibility
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
                socket.send(new DatagramPacket(initPacket, initPacket.length, destinationAddress, destinationPort));
                sentBytesWithHeaders += initPacket.length;
                System.out.printf("Data packets: %d%n", maxSeq);

                // ===== TRY THE SLIDING-WINDOW FAST PATH =====
                // Probe whether the receiver supports ACK-based windowing. If so, run the
                // windowed sender and finish; otherwise fall through to the legacy blast +
                // NAK-rounds path, which also works against non-ACK receivers.
                if (probeAck(socket, transId, initPacket, destinationAddress, destinationPort)) {
                    windowedSend(socket, file, transId, maxSeq, fileSize,
                            destinationAddress, destinationPort, transferStart);
                    return;
                }
                System.out.println("Mode: legacy blast + NAK repair (receiver did not advertise ACK)");

                // ===== INITIALIZE MD5 HASHER =====
                // We compute the MD5 hash as we send, to avoid reading file twice
                Md5State md5 = new Md5State();

                // ===== PREPARE DATA PACKET BUFFERS =====
                byte[] buffer = new byte[MAX_DATA_PAYLOAD];  // Buffer for reading file chunks
                byte[] dataPacket = new byte[HEADER_DATA_BYTES + MAX_DATA_PAYLOAD];  // Full packet buffer

                // Create a ByteBuffer view for the header (first 6 bytes)
                ByteBuffer header = ByteBuffer.wrap(dataPacket).order(ByteOrder.BIG_ENDIAN);
                header.putShort((short) transId);  // Write transaction ID to header

                // ===== CORE SEND LOOP =====
                // Blast the data packets out, computing the MD5 as we go. Anything lost
                // here will be repaired in the control phase below via NAK retransmits.
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
                    header.position(2);  // Skip to seq field (after trans_id)
                    header.putInt((int) seq);  // Write sequence number
                    System.arraycopy(buffer, 0, dataPacket, HEADER_DATA_BYTES, read);

                    // ===== SEND DATA PACKET (or drop it for the loss test) =====
                    if (dropPct > 0 && rng.nextInt(100) < dropPct) {
                        droppedCount++;  // Pretend lost; receiver will NAK it later
                    } else {
                        socket.send(new DatagramPacket(dataPacket, HEADER_DATA_BYTES + read, destinationAddress, destinationPort));
                        sentBytesWithHeaders += HEADER_DATA_BYTES + read;
                    }

                    // ===== RATE LIMITING =====
                    // Without pacing, a tight send loop overflows the kernel socket buffer.
                    if (!pauseBetweenPackets(paceMs)) {
                        break;  // If interrupted, stop sending
                    }
                }

                // ===== BUILD AND SEND FINAL PACKET =====
                //   - trans_id, seq = maxSeq+1 (marks final), md5 = 16-byte hash
                byte[] digest = md5.finish();  // Finalize MD5 hash
                byte[] finalPacket = ByteBuffer.allocate(FINAL_PACKET_BYTES)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putShort((short) transId)  // Transaction ID
                        .putInt((int) (maxSeq + 1))  // Special sequence number (indicates final packet)
                        .put(digest)  // Append 16-byte MD5 hash
                        .array();
                DatagramPacket finalDatagram = new DatagramPacket(finalPacket, finalPacket.length, destinationAddress, destinationPort);
                socket.send(finalDatagram);
                sentBytesWithHeaders += FINAL_PACKET_BYTES;

                if (droppedCount > 0L) {
                    System.out.printf("Simulated loss: dropped %d of %d data packets on first pass (DROP_PCT=%d)%n",
                            droppedCount, maxSeq, dropPct);
                }

                // ===== CONTROL PHASE: WAIT FOR ACK/NAK AND REPAIR =====
                int retransmitted = runControlLoop(socket, file, transId, maxSeq,
                        finalDatagram, destinationAddress, destinationPort);

                // ===== PRINT TRANSFER COMPLETION SUMMARY =====
                long elapsedMs = System.currentTimeMillis() - transferStart;
                double elapsedSec = Math.max(0.001, elapsedMs / 1000.0);  // Avoid division by zero
                if (retransmitted >= 0) {
                    System.out.println("Receiver confirmed transfer COMPLETE (ACK received).");
                    if (retransmitted > 0) {
                        System.out.printf("Retransmitted %d packet(s) in response to NAKs.%n", retransmitted);
                    }
                } else {
                    System.out.println("No ACK received; assuming fire-and-forget receiver and exiting.");
                }
                System.out.println("Transfer sent. File MD5: " + toHex(digest));
                System.out.printf("Bytes sent (including protocol headers): %d%n", sentBytesWithHeaders);
                System.out.printf("Elapsed time: %.3f seconds%n", elapsedSec);
                System.out.printf("Average throughput: %.2f bytes/sec%n", fileSize / elapsedSec);
            }
        }
    }

    /**
     * Control phase: after the file has been blasted out, wait for the receiver's
     * ACK/NAK control packets and retransmit anything it is still missing.
     *
     * Returns the number of packets retransmitted (>= 0) if the receiver confirmed
     * COMPLETE, or -1 if no ACK ever arrived (legacy fire-and-forget receiver), in
     * which case we exit successfully just like the old behaviour.
     */
    private static int runControlLoop(DatagramSocket socket, RandomAccessFile file, int transId,
                                      long maxSeq, DatagramPacket finalDatagram,
                                      InetAddress dest, int destPort) throws Exception {
        socket.setSoTimeout(CTRL_RECV_TIMEOUT_MS);
        byte[] ctlBuf = new byte[5 + 4 * MAX_NAK_SEQS];
        DatagramPacket ctlPacket = new DatagramPacket(ctlBuf, ctlBuf.length);
        int retriesLeft = MAX_RETRIES;
        int retransmitted = 0;

        while (retriesLeft > 0) {
            try {
                socket.receive(ctlPacket);
                int len = ctlPacket.getLength();
                if (len < 5) {
                    continue;  // Too short to be a control header
                }
                ByteBuffer cb = ByteBuffer.wrap(ctlBuf, 0, len).order(ByteOrder.BIG_ENDIAN);
                int ctlTrans = Short.toUnsignedInt(cb.getShort());
                if (ctlTrans != transId) {
                    continue;  // Stale/foreign control packet
                }
                int type = cb.get() & 0xff;

                if (type == CTRL_COMPLETE) {
                    return retransmitted;  // Receiver has everything and verified the MD5
                }

                if (type == CTRL_NAK) {
                    int count = Short.toUnsignedInt(cb.getShort());
                    // Clamp to whatever actually fit in the datagram
                    if (len < 5 + 4 * count) {
                        count = (len - 5) / 4;
                    }
                    for (int i = 0; i < count; ++i) {
                        long seq = Integer.toUnsignedLong(cb.getInt());
                        if (seq >= 1 && seq <= maxSeq) {
                            retransmitDataPacket(socket, file, transId, seq, dest, destPort);
                            retransmitted++;
                        }
                    }
                    // Always resend the final packet so the receiver can re-verify
                    socket.send(finalDatagram);
                    retriesLeft = MAX_RETRIES;  // Got a live reply, refill the budget
                }
            } catch (SocketTimeoutException timeout) {
                // No control packet in time: nudge the receiver by resending the final
                // packet, and count down toward the fire-and-forget fallback.
                socket.send(finalDatagram);
                retriesLeft--;
            }
        }
        return -1;  // Never heard back: treat as a legacy fire-and-forget receiver
    }

    /**
     * Rebuild and resend a single data packet for the given sequence number by reading
     * the matching chunk straight from the file (so we never keep the whole file in memory).
     */
    private static void retransmitDataPacket(DatagramSocket socket, RandomAccessFile file, int transId,
                                             long seq, InetAddress dest, int destPort) throws Exception {
        byte[] buffer = new byte[MAX_DATA_PAYLOAD];
        file.seek((seq - 1L) * MAX_DATA_PAYLOAD);  // Each seq maps to a fixed file offset
        int read = file.read(buffer);
        if (read < 0) {
            read = 0;
        }
        byte[] dataPacket = new byte[HEADER_DATA_BYTES + read];
        ByteBuffer.wrap(dataPacket).order(ByteOrder.BIG_ENDIAN)
                .putShort((short) transId)
                .putInt((int) seq);
        System.arraycopy(buffer, 0, dataPacket, HEADER_DATA_BYTES, read);
        socket.send(new DatagramPacket(dataPacket, dataPacket.length, dest, destPort));
    }

    /** Read the DROP_PCT test knob (0-100); first-pass loss simulation. */
    private static int parseDropPct() {
        String env = System.getenv("DROP_PCT");
        if (env == null) {
            return 0;
        }
        try {
            return Math.max(0, Math.min(100, Integer.parseInt(env.trim())));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    /**
     * Probe whether the receiver supports windowing. A capable receiver sends a
     * cumulative ACK as soon as it gets the init packet. We re-send init a few times
     * (so a lost init still gets through) and watch for that first ACK.
     * Returns true if an ACK was seen (use the window), false otherwise (legacy path).
     */
    private static boolean probeAck(DatagramSocket socket, int transId, byte[] initPacket,
                                    InetAddress dest, int port) throws IOException {
        socket.setSoTimeout(PROBE_WAIT_MS);
        byte[] buf = new byte[64];
        DatagramPacket pkt = new DatagramPacket(buf, buf.length);
        for (int attempt = 0; attempt < PROBE_TRIES; ++attempt) {
            try {
                socket.receive(pkt);
                if (pkt.getLength() >= 5) {
                    ByteBuffer b = ByteBuffer.wrap(buf, 0, pkt.getLength()).order(ByteOrder.BIG_ENDIAN);
                    int tr = Short.toUnsignedInt(b.getShort());
                    int type = b.get() & 0xff;
                    if (tr == transId && type == CTRL_ACK) {
                        return true;  // Receiver speaks ACK -> use the window
                    }
                }
            } catch (SocketTimeoutException e) {
                socket.send(new DatagramPacket(initPacket, initPacket.length, dest, port));  // re-send init
            }
        }
        return false;
    }

    /** Resend one already-sent unit: a data packet, or the final packet when seq == maxSeq+1. */
    private static int resendUnit(DatagramSocket socket, RandomAccessFile file, int transId, long seq,
                                  long maxSeq, byte[] finalPacket, InetAddress dest, int port) throws Exception {
        if (seq <= maxSeq) {
            retransmitDataPacket(socket, file, transId, seq, dest, port);
            return 1;
        }
        if (finalPacket != null) {
            socket.send(new DatagramPacket(finalPacket, finalPacket.length, dest, port));
            return 1;
        }
        return 0;
    }

    /**
     * Sliding-window send (Selective Repeat). Keeps up to WINDOW_SIZE data packets in
     * flight, slides the window forward on cumulative ACKs, and repairs losses with
     * TCP-style fast retransmit (3 duplicate ACKs) plus an RTO backstop on the oldest
     * unacked unit. MD5 is computed over the first send of each chunk.
     */
    private static void windowedSend(DatagramSocket socket, RandomAccessFile file, int transId,
                                     long maxSeq, long fileSize, InetAddress dest, int port,
                                     long transferStart) throws Exception {
        System.out.printf("Mode: sliding window (receiver supports ACK), window=%d%n", WINDOW_SIZE);

        long[] sendTime = new long[(int) (maxSeq + 2)];  // ms timestamp per unit; 0 = not sent
        int dropPct = parseDropPct();
        java.util.Random rng = new java.util.Random();
        long dropped = 0, retransmitted = 0;

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] chunk = new byte[MAX_DATA_PAYLOAD];
        byte[] finalPacket = null;
        byte[] digest = null;
        boolean finalBuilt = false, finalSent = false, complete = false;
        long base = 1, nextSeq = 1;
        long progressAt = System.currentTimeMillis();
        int dupAcks = 0;
        boolean fastDone = false;

        socket.setSoTimeout(WIN_RECV_TIMEOUT_MS);
        byte[] cb = new byte[5 + 4 * MAX_NAK_SEQS];
        DatagramPacket cpkt = new DatagramPacket(cb, cb.length);

        while (true) {
            // ===== FILL THE WINDOW WITH NEW DATA =====
            while (nextSeq <= maxSeq && nextSeq < base + WINDOW_SIZE) {
                file.seek((nextSeq - 1L) * MAX_DATA_PAYLOAD);
                int br = file.read(chunk);
                if (br < 0) {
                    br = 0;
                }
                md5.update(chunk, 0, br);  // hash on first send only
                byte[] dp = new byte[HEADER_DATA_BYTES + br];
                ByteBuffer.wrap(dp).order(ByteOrder.BIG_ENDIAN).putShort((short) transId).putInt((int) nextSeq);
                System.arraycopy(chunk, 0, dp, HEADER_DATA_BYTES, br);
                if (dropPct > 0 && rng.nextInt(100) < dropPct) {
                    dropped++;
                } else {
                    socket.send(new DatagramPacket(dp, dp.length, dest, port));
                }
                sendTime[(int) nextSeq] = System.currentTimeMillis();
                nextSeq++;
            }

            // ===== BUILD AND SEND THE FINAL PACKET ONCE ALL DATA IS HASHED =====
            if (nextSeq > maxSeq && !finalBuilt) {
                digest = md5.digest();
                finalPacket = ByteBuffer.allocate(FINAL_PACKET_BYTES).order(ByteOrder.BIG_ENDIAN)
                        .putShort((short) transId).putInt((int) (maxSeq + 1)).put(digest).array();
                finalBuilt = true;
            }
            if (finalBuilt && !finalSent) {
                socket.send(new DatagramPacket(finalPacket, finalPacket.length, dest, port));
                sendTime[(int) (maxSeq + 1)] = System.currentTimeMillis();
                finalSent = true;
            }

            // ===== RECEIVE A CONTROL PACKET =====
            boolean got = true;
            try {
                socket.receive(cpkt);
            } catch (SocketTimeoutException e) {
                got = false;
            }
            if (got && cpkt.getLength() >= 5) {
                ByteBuffer b = ByteBuffer.wrap(cb, 0, cpkt.getLength()).order(ByteOrder.BIG_ENDIAN);
                int tr = Short.toUnsignedInt(b.getShort());
                if (tr == transId) {
                    int type = b.get() & 0xff;
                    if (type == CTRL_COMPLETE) {
                        complete = true;
                        break;
                    } else if (type == CTRL_ACK && cpkt.getLength() >= 9) {
                        b.getShort();  // count (unused)
                        long ackBase = Integer.toUnsignedLong(b.getInt());
                        if (ackBase > base) {
                            base = ackBase;            // slide the window forward
                            progressAt = System.currentTimeMillis();
                            dupAcks = 0;
                            fastDone = false;
                        } else if (ackBase == base) {
                            // Duplicate ACK: receiver stuck on `base`. Fast-retransmit once.
                            if (++dupAcks >= 3 && !fastDone && base <= maxSeq + 1) {
                                retransmitted += resendUnit(socket, file, transId, base, maxSeq, finalPacket, dest, port);
                                sendTime[(int) base] = System.currentTimeMillis();
                                fastDone = true;
                            }
                        }
                    } else if (type == CTRL_NAK) {
                        int count = Short.toUnsignedInt(b.getShort());
                        if (cpkt.getLength() < 5 + 4 * count) {
                            count = (cpkt.getLength() - 5) / 4;
                        }
                        for (int i = 0; i < count; ++i) {
                            long s = Integer.toUnsignedLong(b.getInt());
                            if (s >= 1 && s <= maxSeq) {
                                retransmitted += resendUnit(socket, file, transId, s, maxSeq, finalPacket, dest, port);
                                sendTime[(int) s] = System.currentTimeMillis();
                            }
                        }
                        if (finalBuilt) {
                            socket.send(new DatagramPacket(finalPacket, finalPacket.length, dest, port));
                        }
                    }
                }
            }

            // ===== RTO BACKSTOP ON THE OLDEST UNACKED UNIT =====
            long now = System.currentTimeMillis();
            long upto = finalSent ? maxSeq + 1 : (nextSeq > 1 ? nextSeq - 1 : 1);
            if (base <= upto && sendTime[(int) base] > 0 && now - sendTime[(int) base] > RTO_MS) {
                retransmitted += resendUnit(socket, file, transId, base, maxSeq, finalPacket, dest, port);
                sendTime[(int) base] = now;
                fastDone = false;
            }

            // ===== STALL GUARD =====
            if (System.currentTimeMillis() - progressAt > WIN_STALL_ABORT_MS) {
                System.err.println("windowed: no progress, aborting.");
                break;
            }
        }

        // ===== SUMMARY =====
        double elapsedSec = Math.max(0.001, (System.currentTimeMillis() - transferStart) / 1000.0);
        if (dropped > 0) {
            System.out.printf("Simulated loss: dropped %d data packets on first pass (DROP_PCT=%d)%n", dropped, dropPct);
        }
        if (retransmitted > 0) {
            System.out.printf("Retransmitted %d packet(s) (window RTO/NAK).%n", retransmitted);
        }
        System.out.println(complete
                ? "Receiver confirmed transfer COMPLETE (ACK/window)."
                : "Windowed transfer ended without COMPLETE.");
        if (digest != null) {
            System.out.println("Transfer sent. File MD5: " + toHex(digest));
        }
        System.out.printf("Elapsed time: %.3f seconds%n", elapsedSec);
        System.out.printf("Average throughput: %.2f bytes/sec%n", fileSize / elapsedSec);
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