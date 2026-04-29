Sender and Receiver Commands For Each Project

=== C ===
--- Receiver --- 
+ ./udp_rx.exe 9000 ./received 30000
--- Sender ---
+ ./udp_tx.exe 127.0.0.1 9000 demodemo.txt <ms> (1 ms required for go)

=== Java (Misha)===
--- Receiver ---
+ java -cp . UdpFileReceiver 9000 ./received 30000
--- Sender ---
+ java -cp . UdpFileSender 127.0.0.1 9000 demodemo.txt <ms>

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
