# Multi-Threaded Encrypted Secure File Transfer System

A high-performance, production-grade command-line utility built from scratch in C++ using the raw Windows Sockets (Winsock) API. The system establishes a secure connection, validates data integrity, handles concurrent clients via native multithreading, and natively recovers interrupted transfers through custom protocol checkpointing.

## 🚀 Key Features

- **Object-Oriented Architecture:** Fully decoupled, encapsulated classes for structural state management.
- **Diffie-Hellman Cryptographic Handshake:** Secure key exchange to dynamically establish symmetric session keys over an insecure network.
- **On-the-Fly Encryption:** High-throughput streaming cipher targeting 64KB data block arrays.
- **Resumable Transfers:** Custom protocol metadata negotiation allows automatic check-pointing and recovery of incomplete `.part` transfers.
- **Thread-Safe Audit Log:** Utilizes native Critical Section Mutex locks to record timestamped system transactions safely across concurrent sessions.
- **Bit-for-Bit Validation:** Native FNV-1a 64-bit checksum engine validation post-transfer.

## 🛠️ Technical Prerequisites & Setup

Ensure you are working in a Windows environment with the `g++` compiler configured in your path variables.

### Compilation
Compile the binaries using maximum compiler optimizations (`-O3`) and linking the Windows network interface layer (`-lws2_32`):

```powershell
g++ src/server.cpp -o server.exe -lws2_32 -O3
g++ src/client.cpp -o client.exe -lws2_32 -O3