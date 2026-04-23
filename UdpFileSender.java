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

// cap the payload at 1400 bytes
// usual MTU is 1500 bytes
// stopping at 1400 leaves enough room for IP and UDP headers
// to reduce risk of the OS or routers fragmenting the packets
public final class UdpFileSender {
    private static final int HEADER_DATA_BYTES = 6;
    private static final int FINAL_PACKET_BYTES = 22;
    private static final int RATE_LIMIT_MS = 1;
    private static final int MAX_DATA_PAYLOAD = 1400;
    private static final int MIN_INIT_FILENAME = 8;
    private static final int MAX_INIT_FILENAME = 2048;

    private static final class Md5State {
        private final MessageDigest digest;

        Md5State() throws NoSuchAlgorithmException {
            this.digest = MessageDigest.getInstance("MD5");
        }

        void update(byte[] data, int length) {
            digest.update(data, 0, length);
        }

        byte[] finish() {
            return digest.digest();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4 || args.length > 5) {
            System.err.println("Usage: java UdpFileSender <dest_ip> <dest_port> <source_file> <tx_id> [pace_ms]");
            System.exit(1);
        }

        InetAddress destinationAddress = InetAddress.getByName(args[0]);
        int destinationPort = Integer.parseInt(args[1]);
        String sourceFile = args[2];
        int transId = Integer.parseInt(args[3]) & 0xffff;
        int paceMs = args.length == 5 ? Integer.parseInt(args[4]) : RATE_LIMIT_MS;
        if (paceMs < 0) {
            throw new IllegalArgumentException("pace_ms must be >= 0");
        }

        String fileNameOnly = Paths.get(sourceFile).getFileName().toString();
        byte[] filenameBytes = fileNameOnly.getBytes(StandardCharsets.UTF_8);
        if (filenameBytes.length < MIN_INIT_FILENAME || filenameBytes.length > MAX_INIT_FILENAME) {
            throw new IllegalArgumentException("Filename length must be between 8 and 2048 bytes");
        }

        InetSocketAddress remote = new InetSocketAddress(destinationAddress, destinationPort);
        long transferStart = System.currentTimeMillis();
        long sentBytesWithHeaders = 0L;

        System.out.println("Starting UDP transfer");
        System.out.printf("Destination: %s:%d%n", destinationAddress.getHostAddress(), destinationPort);
        System.out.printf("File: %s (%d bytes)%n", fileNameOnly, Paths.get(sourceFile).toFile().length());
        System.out.printf("Transaction ID: %d%n", transId);
        System.out.printf("Packet pacing: %d ms%n", paceMs);

        try (DatagramChannel channel = DatagramChannel.open()) {
            channel.configureBlocking(true);

            try (RandomAccessFile file = new RandomAccessFile(sourceFile, "r")) {
                long fileSize = file.length();
                // calculate how many chunks are needed to send the whole file
                long maxSeq = (fileSize + MAX_DATA_PAYLOAD - 1L) / MAX_DATA_PAYLOAD;
                
                // interoperability: forcing the ByteBuffer to use BIG_ENDIAN
                // which is the standard Network Byte Order
                // C is x86 (little-endian) machine, it would result in
                // completely garbled sequence numbers and transaction IDs
                // without this force
                byte[] initPacket = ByteBuffer.allocate(10 + filenameBytes.length)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putShort((short) transId)
                        .putInt(0)
                        .putInt((int) maxSeq)
                        .put(filenameBytes)
                        .array();
                channel.send(ByteBuffer.wrap(initPacket), remote);
                    sentBytesWithHeaders += initPacket.length;
                    System.out.printf("Data packets: %d%n", maxSeq);

                Md5State md5 = new Md5State();
                byte[] buffer = new byte[MAX_DATA_PAYLOAD];
                    byte[] dataPacket = new byte[HEADER_DATA_BYTES + MAX_DATA_PAYLOAD];
                ByteBuffer header = ByteBuffer.wrap(dataPacket).order(ByteOrder.BIG_ENDIAN);
                header.putShort((short) transId);

                // core fire and forget loop
                // NO ACKs and no retransmits allowed, blasting the data sequentially

                for (long seq = 1; seq <= maxSeq; ++seq) {
                    int read = file.read(buffer);
                    if (read < 0) {
                        read = 0;
                    }
                    
                    // instead of reading the file twice (once for sending, a second time for hashing)
                    // update MD5 dynamically here
                    md5.update(buffer, read);
                    header.position(2);
                    header.putInt((int) seq);
                    System.arraycopy(buffer, 0, dataPacket, HEADER_DATA_BYTES, read);
                    channel.send(ByteBuffer.wrap(dataPacket, 0, HEADER_DATA_BYTES + read), remote);
                    sentBytesWithHeaders += HEADER_DATA_BYTES + read;

                    // rate limiting
                    // to prevent OS socket overflow and buffer
                    // 1ms delay to give the network space, since there are no ACKs doing so
                    if (!pauseBetweenPackets(paceMs)) {
                        break;
                    }
                }

                // Final packet closure
                // transports the MD5 digest
                // if anything of the fire-and-forget packets were dropped,
                // the receiver's hash will catch it here
                byte[] digest = md5.finish();
                ByteBuffer finalPacket = ByteBuffer.allocate(FINAL_PACKET_BYTES)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putShort((short) transId)
                        .putInt((int) (maxSeq + 1))
                        .put(digest);
                channel.send((ByteBuffer) finalPacket.flip(), remote);
                sentBytesWithHeaders += FINAL_PACKET_BYTES;

                long elapsedMs = System.currentTimeMillis() - transferStart;
                double elapsedSec = Math.max(0.001, elapsedMs / 1000.0);
                System.out.println("Transfer sent. File MD5: " + toHex(digest));
                System.out.printf("Bytes sent (including protocol headers): %d%n", sentBytesWithHeaders);
                System.out.printf("Elapsed time: %.3f seconds%n", elapsedSec);
                System.out.printf("Average throughput: %.2f bytes/sec%n", fileSize / elapsedSec);
            }
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    private static boolean pauseBetweenPackets(int paceMs) {
        try {
            if (paceMs > 0) {
                Thread.sleep(paceMs);
            }
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Sender was interrupted.");
            return false;
        }
    }
}