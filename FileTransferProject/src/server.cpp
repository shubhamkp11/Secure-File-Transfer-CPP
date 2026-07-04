#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <string>
#include <ctime>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")

// Encapsulated Cryptographic Utility Layer
class CryptoEngine {
public:
    static long long powerMod(long long base, long long exp, long long mod) {
        long long res = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1) res = (res * base) % mod;
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return res;
    }

    static unsigned long long calculateFNV1aHash(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return 0;
        
        unsigned long long hash = 14695981039346656037ULL;
        char buffer[4096];
        
        while (file.good()) {
            file.read(buffer, sizeof(buffer));
            std::streamsize bytesRead = file.gcount();
            for (std::streamsize i = 0; i < bytesRead; ++i) {
                hash ^= static_cast<unsigned char>(buffer[i]);
                hash *= 1099511628211ULL;
            }
        }
        return hash;
    }

    static void transformBuffer(char* buffer, int size, char key) {
        for (int i = 0; i < size; ++i) {
            buffer[i] ^= key;
        }
    }
};

// Protocol Data Layout Struct
struct FileMetadata {
    char filename[256];
    long long fileSize;
    unsigned long long fileHash;
};

// Thread Isolation Session Worker
class ClientSession {
private:
    SOCKET sessionSocket;
    int sessionId;
    CRITICAL_SECTION* globalLogMutex;
    char secretKey;

    void logEvent(const std::string& action, const std::string& details) {
        EnterCriticalSection(globalLogMutex);
        std::ofstream logFile("server_audit.log", std::ios::app);
        time_t now = time(0);
        char* dt = ctime(&now);
        std::string timestamp(dt);
        timestamp.pop_back(); 
        logFile << "[" << timestamp << "] [Session " << sessionId << "] " << action << " : " << details << "\n";
        logFile.close();
        LeaveCriticalSection(globalLogMutex);
    }

    bool executeKeyExchange() {
        long long P = 23; long long G = 5; long long serverPrivateKey = 15;
        long long serverPublicKey = CryptoEngine::powerMod(G, serverPrivateKey, P);
        long long clientPublicKey;
        
        if (recv(sessionSocket, (char*)&clientPublicKey, sizeof(clientPublicKey), 0) <= 0) return false;
        if (send(sessionSocket, (char*)&serverPublicKey, sizeof(serverPublicKey), 0) == SOCKET_ERROR) return false;
        
        secretKey = (char)CryptoEngine::powerMod(clientPublicKey, serverPrivateKey, P);
        logEvent("SECURE", "Key Exchange completed smoothly.");
        return true;
    }

public:
    ClientSession(SOCKET socket, int id, CRITICAL_SECTION* mutex) 
        : sessionSocket(socket), sessionId(id), globalLogMutex(mutex), secretKey(0) {}

    ~ClientSession() {
        if (sessionSocket != INVALID_SOCKET) {
            closesocket(sessionSocket);
        }
    }

    void ProcessContext() {
        logEvent("CONNECT", "Session established with client interface.");
        
        if (!executeKeyExchange()) {
            logEvent("ERROR", "Security key exchange initialization mapping aborted.");
            return;
        }

        FileMetadata meta;
        if (recv(sessionSocket, (char*)&meta, sizeof(FileMetadata), 0) <= 0) {
            logEvent("ERROR", "Failed to resolve metadata handshake segment.");
            return;
        }

        std::string originalName(meta.filename);
        std::string tempName = std::to_string(meta.fileHash) + ".part";
        std::string finalName = "completed_" + originalName;
        long long resumeOffset = 0;

        std::ifstream checkFile(tempName, std::ios::binary | std::ios::ate);
        if (checkFile) {
            resumeOffset = checkFile.tellg();
            checkFile.close();
            logEvent("RESUME", "Partial segment located. Requesting sync offset: " + std::to_string(resumeOffset));
        } else {
            logEvent("NEW_FILE", "Initializing allocation block for: " + originalName);
        }

        send(sessionSocket, (char*)&resumeOffset, sizeof(resumeOffset), 0);

        std::ofstream outfile(tempName, std::ios::binary | std::ios::app);
        char buffer[65536];
        int bytesReceived;
        long long cumulativeBytes = resumeOffset;

        while ((bytesReceived = recv(sessionSocket, buffer, sizeof(buffer), 0)) > 0) {
            CryptoEngine::transformBuffer(buffer, bytesReceived, secretKey);
            outfile.write(buffer, bytesReceived);
            cumulativeBytes += bytesReceived;
        }
        outfile.close();

        if (cumulativeBytes < meta.fileSize) {
            logEvent("DISCONNECT", "Stream disconnected at byte index: " + std::to_string(cumulativeBytes));
        } else {
            logEvent("VERIFYING", "Stream complete. Testing signature matching verification parameters...");
            if (CryptoEngine::calculateFNV1aHash(tempName) == meta.fileHash) {
                std::remove(finalName.c_str());
                std::rename(tempName.c_str(), finalName.c_str());
                logEvent("INTEGRITY_SUCCESS", "Data validation matched perfectly. Target locked: " + finalName);
            } else {
                logEvent("INTEGRITY_FAIL", "Data structural breakdown encountered. Checksum payload fault.");
            }
        }
    }
};

// Orchestration Context Layer
class SecureServer {
private:
    SOCKET listenSocket;
    CRITICAL_SECTION logMutex;
    int sessionCounter;
    bool isRunning;

    struct ThreadParams {
        ClientSession* sessionInstance;
    };

    static DWORD WINAPI HandleClientThunk(LPVOID lpParam) {
        ThreadParams* params = reinterpret_cast<ThreadParams*>(lpParam);
        if (params && params->sessionInstance) {
            params->sessionInstance->ProcessContext();
            delete params->sessionInstance; // Deallocate dynamic worker context cleanly inside the thread scope
        }
        delete params;
        return 0;
    }

public:
    SecureServer() : listenSocket(INVALID_SOCKET), sessionCounter(1), isRunning(false) {
        InitializeCriticalSection(&logMutex);
    }

    ~SecureServer() {
        Stop();
        DeleteCriticalSection(&logMutex);
    }

    bool Start(int port) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

        listenSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (listenSocket == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);

        if (bind(listenSocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(listenSocket);
            WSACleanup();
            return false;
        }

        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSocket);
            WSACleanup();
            return false;
        }

        isRunning = true;
        std::cout << "OOP Architecture Engine listening on port " << port << "...\n";

        while (isRunning) {
            SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
            if (clientSocket != INVALID_SOCKET) {
                ClientSession* newSession = new ClientSession(clientSocket, sessionCounter++, &logMutex);
                ThreadParams* params = new ThreadParams{ newSession };
                
                CreateThread(NULL, 0, HandleClientThunk, params, 0, NULL);
            }
        }
        return true;
    }

    void Stop() {
        if (isRunning) {
            isRunning = false;
            if (listenSocket != INVALID_SOCKET) {
                closesocket(listenSocket);
                listenSocket = INVALID_SOCKET;
            }
            WSACleanup();
        }
    }
};

int main() {
    SecureServer server;
    server.Start(8080);
    return 0;
}