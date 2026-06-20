Sender and Receiver Commands For Each Project

=== C ===
--- Build ---
+ gcc -Wall -Wextra -O2 -o udp_tx.exe udp_tx.c -lws2_32
+ gcc -Wall -Wextra -O2 -o udp_rx.exe udp_rx.c -lws2_32

--- Receiver ---   udp_rx.exe <port> [out_dir] [idle_timeout_ms] [loop]
+ ./udp_rx.exe 9000 ./received 40000          (one transfer, then exits)
+ ./udp_rx.exe 9000 ./received 40000 loop     (stays up for many transfers; Ctrl+C to stop)
  Saves to <out_dir>/received_files/ and verifies the MD5 before writing.

--- Sender ---     udp_tx.exe <dest_ip> <dest_port> <file> [pace_ms]
+ ./udp_tx.exe 127.0.0.1 9000 demodemo.txt 1
  pace_ms is only used on the legacy fallback path (the window self-paces).

=== Java (Misha)===
--- Build ---
+ javac UdpFileSender.java UdpFileReceiver.java

--- Receiver ---   java UdpFileReceiver <port> [out_dir] [idle_timeout_ms] [loop]
+ java -cp . UdpFileReceiver 9000 ./received 40000          (one transfer, then exits)
+ java -cp . UdpFileReceiver 9000 ./received 40000 loop     (stays up; Ctrl+C to stop)

--- Sender ---     java UdpFileSender <dest_ip> <dest_port> <file> <tx_id> [pace_ms]
+ java -cp . UdpFileSender 127.0.0.1 9000 demodemo.txt 7 1
  (tx_id is any number 0-65535; it labels the transfer.)

=== Go ===
--- Receiver ---
+ go run . receiver
--- Sender ---
+ go run . sender demodemo.txt
NOTE: Go receiver is running in port 9000 repeatedly, unless you taskkill.

=== Java (Maven) ===
--- Receiver ---
+ java -cp "target/udp-1.0-SNAPSHOT.jar;target/dependency/*" udp.project.MainRX 9000 
--- Sender ---
+ java -cp "target/udp-1.0-SNAPSHOT.jar;target/dependency/*" udp.project.MainTX
  host  → 127.0.0.1
  port  → 9000
  delay → <ms>
  file  → demodemo.txt
  file  → exit


Build Commands
**Compile C programs:**
```bash
gcc -Wall -Wextra -O2 -o udp_tx.exe udp_tx.c -lws2_32
gcc -Wall -Wextra -O2 -o udp_rx.exe udp_rx.c -lws2_32
```

**Compile (Misha) Java programs:**
```bash
javac UdpFileSender.java
javac UdpFileReceiver.java 


**Compile Go programs:**
go mod tidy

**Compile (Islam) Java Programs:**
mvn -DskipTests package


====================================================================
Features & Testing  (applies to the C and Java (Misha) versions)
====================================================================

How a transfer works
--------------------
1. Reliability (always on): the receiver acknowledges packets and requests
   anything missing (ACK/NAK), so transfers are error-free even with packet loss.
   The file is MD5-verified before it is saved.
2. Speed (auto-negotiated): if the receiver advertises ACK support, the sender
   uses a sliding window (Selective Repeat). You'll see this line on the sender:
       Mode: sliding window (receiver supports ACK), window=64
   Against a receiver that doesn't ACK, the sender prints
       Mode: legacy blast + NAK repair (receiver did not advertise ACK)
   and still completes (or exits cleanly if nobody is listening).
3. Success looks like:  the sender prints
       Receiver confirmed transfer COMPLETE (ACK/window).
   and the receiver prints  Transfer complete: ... / MD5 verified.

Keep the receiver running for multiple transfers
------------------------------------------------
Add `loop` (or -l / --loop) as the last argument so one receiver handles
back-to-back sends without restarting (Ctrl+C to stop):
+ ./udp_rx.exe 9000 ./received 40000 loop
+ java -cp . UdpFileReceiver 9000 ./received 40000 loop

Simulate packet loss (DROP_PCT)  — set on the SENDER
----------------------------------------------------
DROP_PCT (0-100) randomly drops that % of data packets on the first pass.
Retransmits are never dropped, so the file must still arrive intact.

PowerShell:
    $env:DROP_PCT=30; .\udp_tx.exe 127.0.0.1 9000 demodemo.txt 1; Remove-Item Env:\DROP_PCT
Git Bash:
    DROP_PCT=30 ./udp_tx.exe 127.0.0.1 9000 demodemo.txt 1
Watch for:  "Simulated loss: dropped N ..."  then  "Retransmitted M ...".

Verify the received file is identical
-------------------------------------
PowerShell:
    Get-FileHash demodemo.txt -Algorithm MD5
    Get-ChildItem received\received_files | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-FileHash -Algorithm MD5
The two Hash values must match.

Automated test (all four C<->Java combinations)
-----------------------------------------------
    .\test.ps1                 # all 4 combos, no loss
    .\test.ps1 -Drop 30        # all 4 combos with 30% simulated loss
    .\test.ps1 -Build -Drop 50 -SizeMB 5
It builds, generates a random test file, runs each combination, and prints
PASS/FAIL by comparing MD5 hashes.

Tips
----
- Only one process can bind port 9000. If a receiver is stuck:
  taskkill /F /IM udp_rx.exe   (or close that terminal / Stop-Process java)
- Clear the output folder between runs to keep plain filenames, otherwise the
  receiver appends a suffix to avoid overwriting:  Remove-Item received -Recurse -Force
