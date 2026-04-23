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

public final class UdpFileReceiver {
    // Packet sizes come directly from the protocol schema.
    private static final int HEADER_INIT_BYTES = 10;
    private static final int HEADER_DATA_BYTES = 6;
    private static final int FINAL_BYTES = 22;
    private static final int MAX_DATA_PAYLOAD = 1400;
    private static final int MIN_INIT_FILENAME = 8;
    private static final int MAX_INIT_FILENAME = 2048;
    private static final String RECEIVED_DIR = "received_files";

    private static final class Session {
        long transId = -1L;
        long maxSeq = -1L;
        String filename;
        final Map<Long, byte[]> chunks = new HashMap<>();
        byte[] finalMd5;
        boolean initSeen;
        boolean finalSeen;

        boolean isReadyToFinish() {
            // Transfer is complete only when all required states and chunks are present
            return initSeen && finalSeen && maxSeq >= 0 && chunks.size() == maxSeq;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 3) {
            System.err.println("Usage: java UdpFileReceiver <listen_port> [output_dir] [idle_timeout_ms]");
            System.exit(1);
        }

        int listenPort = Integer.parseInt(args[0]);
        Path outputDir = Paths.get(args.length >= 2 ? args[1] : ".");
        int idleTimeoutMs = args.length >= 3 ? Integer.parseInt(args[2]) : 3000;
        long transferStart = System.currentTimeMillis();

        Files.createDirectories(outputDir);
        Path scopedReceiveDir = outputDir.resolve(RECEIVED_DIR);
        Files.createDirectories(scopedReceiveDir);

        System.out.println("UDP File Receiver starting...");
        System.out.printf("Listening on port: %d%n", listenPort);
        System.out.printf("Output scope: %s%n", scopedReceiveDir.toAbsolutePath());
        System.out.printf("Idle timeout: %d ms%n", idleTimeoutMs);

        Session session = new Session();
        byte[] buffer = new byte[4096];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        try (DatagramSocket socket = new DatagramSocket(listenPort)) {
            socket.setSoTimeout(500);
            long lastPacketAt = System.currentTimeMillis();

            while (true) {
                try {
                    socket.receive(packet);
                    lastPacketAt = System.currentTimeMillis();
                    handlePacket(session, packet.getData(), packet.getLength());
                    if (session.isReadyToFinish()) {
                        finishTransfer(session, scopedReceiveDir, transferStart);
                        return;
                    }
                } catch (SocketTimeoutException timeout) {
                    // idle timeout to safely terminate corrupted transfers
                    // without this, a lost packet'll mean the sender won't resend it (we use fire-and-forget)
                    // and the receiver would wait forever
                    if (session.initSeen && System.currentTimeMillis() - lastPacketAt > idleTimeoutMs) {
                        if (session.isReadyToFinish()) {
                            finishTransfer(session, scopedReceiveDir, transferStart);
                        } else {
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

    private static void handlePacket(Session session, byte[] data, int length) throws NoSuchAlgorithmException {
        if (length < HEADER_DATA_BYTES) {
            return;
        }

        // interoperability contraints
        // forcing the ByteBuffer to use Big-Endian
        // to match the C transmitter's htonl() network byte formatting
        ByteBuffer buffer = ByteBuffer.wrap(data, 0, length).order(ByteOrder.BIG_ENDIAN);
        int transId = Short.toUnsignedInt(buffer.getShort());
        // java doesn't have native unsigned 32-bit integer
        // lifting the 32-bit seq number into a 64-bit length
        // to prevent overflow and becoming negative
        long seq = Integer.toUnsignedLong(buffer.getInt());

        if (!session.initSeen) {
            // The first valid packet must be INIT: Seq=0, includes MaxSeq and filename.
            if (seq != 0L || length < HEADER_INIT_BYTES) {
                return;
            }

            long maxSeq = Integer.toUnsignedLong(buffer.getInt());
            byte[] filenameBytes = Arrays.copyOfRange(data, HEADER_INIT_BYTES, length);
            if (filenameBytes.length < MIN_INIT_FILENAME || filenameBytes.length > MAX_INIT_FILENAME) {
                return;
            }

            String filename = new String(filenameBytes, StandardCharsets.UTF_8);

            session.transId = Integer.toUnsignedLong(transId);
            session.maxSeq = maxSeq;
            session.filename = filename;
            session.initSeen = true;
            return;
        }

        // Ignore packets that belong to a different transaction ID
        if (Integer.toUnsignedLong(transId) != session.transId) {
            return;
        }

        // FINAL packet convention: Seq=MaxSeq+1 and payload is 16-byte MD5
        if (seq == session.maxSeq + 1L && length == FINAL_BYTES) {
            byte[] md5 = Arrays.copyOfRange(data, HEADER_DATA_BYTES, FINAL_BYTES);
            session.finalMd5 = md5;
            session.finalSeen = true;
            return;
        }

        if (seq == 0L || seq > session.maxSeq) {
            return;
        }

        int payloadLength = length - HEADER_DATA_BYTES;
        if (payloadLength < 0 || payloadLength > MAX_DATA_PAYLOAD) {
            return;
        }

        // UDP can reorder packets
        // instead of writing them immediately, they are stashed into the Hashmap
        // keyed with their sequence index
        // so that the arrival order no longer matters
        session.chunks.putIfAbsent(seq, Arrays.copyOfRange(data, HEADER_DATA_BYTES, length));
    }

    private static void finishTransfer(Session session, Path receiveDir, long transferStart) throws IOException, NoSuchAlgorithmException {
        if (!session.isReadyToFinish()) {
            throw new IllegalStateException("Transfer is not complete.");
        }

        long totalLength = 0L;
        for (long seq = 1L; seq <= session.maxSeq; ++seq) {
            byte[] chunk = session.chunks.get(seq);
            if (chunk == null) {
                throw new IllegalStateException("Missing chunk " + seq);
            }
            totalLength += chunk.length;
        }

        if (totalLength > Integer.MAX_VALUE) {
            throw new IllegalStateException("File too large to assemble in memory.");
        }

        // Rebuild exact byte stream in ascending sequence order
        byte[] fileBytes = new byte[(int) totalLength];
        int offset = 0;
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        // Deterministic reassembly order ensures reproducible output and digest
        for (long seq = 1L; seq <= session.maxSeq; ++seq) {
            byte[] chunk = session.chunks.get(seq);
            System.arraycopy(chunk, 0, fileBytes, offset, chunk.length);
            md5.update(chunk);
            offset += chunk.length;
        }

        byte[] computed = md5.digest();
        // Integrity guard: final sender MD5 must match receiver-computed MD5.
        // if a fire-and-forget packet was corrupted in transit and wasn't listened,
        // this will catch it and throw it out
        if (!Arrays.equals(computed, session.finalMd5)) {
            throw new IllegalStateException("MD5 mismatch. Transfer corrupted.");
        }

        System.out.println("MD5 received: " + toHex(session.finalMd5));
        System.out.println("MD5 computed: " + toHex(computed));

        Path namePath = Paths.get(session.filename).getFileName();
        String safeName = namePath == null ? "received.bin" : namePath.toString();
        if (safeName.isEmpty()) {
            safeName = "received.bin";
        }

        Path outputFile = uniqueOutputPath(receiveDir, safeName);
        Files.write(outputFile, fileBytes);

        double elapsedSec = Math.max(0.001, (System.currentTimeMillis() - transferStart) / 1000.0);
        System.out.println("Transfer complete: " + outputFile);
        System.out.println("MD5 verified: " + toHex(computed));
        System.out.printf("File size: %d bytes%n", totalLength);
        System.out.printf("Packets received: %d%n", session.maxSeq);
        System.out.printf("Elapsed time: %.3f seconds%n", elapsedSec);
        System.out.printf("Transfer rate: %.2f bytes/sec%n", totalLength / elapsedSec);
    }

    private static Path uniqueOutputPath(Path dir, String fileName) throws IOException {
        Path candidate = dir.resolve(fileName).normalize();
        if (!Files.exists(candidate)) {
            return candidate;
        }

        String stem = fileName;
        String ext = "";
        int dot = fileName.lastIndexOf('.');
        if (dot > 0) {
            stem = fileName.substring(0, dot);
            ext = fileName.substring(dot);
        }

        String suffix = "_" + System.currentTimeMillis();
        candidate = dir.resolve(stem + suffix + ext).normalize();
        int index = 1;
        while (Files.exists(candidate)) {
            candidate = dir.resolve(stem + suffix + "_" + index + ext).normalize();
            index++;
        }
        return candidate;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }
}