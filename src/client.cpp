#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <cstring>  
#include <string>

#pragma comment(lib, "ws2_32.lib")

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

struct FileMetadata {
    char filename[256];
    long long fileSize;
    unsigned long long fileHash;
};

class SecureClient {
private:
    SOCKET clientSocket;
    char secretKey;
    std::string targetPath;

    bool initializeSessionKey() {
        long long P = 23; long long G = 5; long long clientPrivateKey = 6;
        std::cout << "Negotiating encryption handshake indices...\n";
        
        long long clientPublicKey = CryptoEngine::powerMod(G, clientPrivateKey, P);
        long long serverPublicKey;
        
        if (send(clientSocket, (char*)&clientPublicKey, sizeof(clientPublicKey), 0) == SOCKET_ERROR) return false;
        if (recv(clientSocket, (char*)&serverPublicKey, sizeof(serverPublicKey), 0) <= 0) return false;
        
        secretKey = (char)CryptoEngine::powerMod(serverPublicKey, clientPrivateKey, P);
        return true;
    }

    void renderProgressBar(long long progress, long long total) {
        static int lastPercent = -1;
        int barWidth = 50;
        float ratio = static_cast<float>(progress) / total;
        int currentPercent = static_cast<int>(ratio * 100.0f);

        if (currentPercent > lastPercent) {
            int pos = static_cast<int>(barWidth * ratio);
            std::cout << "\r[";
            for (int i = 0; i < barWidth; ++i) {
                if (i < pos) std::cout << "=";
                else if (i == pos) std::cout << ">";
                else std::cout << " ";
            }
            std::cout << "] " << currentPercent << " %" << std::flush;
            lastPercent = currentPercent;
        }
    }

public:
    SecureClient(const std::string& filepath) : clientSocket(INVALID_SOCKET), secretKey(0), targetPath(filepath) {}

    ~SecureClient() {
        if (clientSocket != INVALID_SOCKET) {
            closesocket(clientSocket);
        }
        WSACleanup();
    }

    bool ConnectAndTransmit(const std::string& ipAddress, int port) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == INVALID_SOCKET) return false;

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        serverAddr.sin_addr.s_addr = inet_addr(ipAddress.c_str());

        if (connect(clientSocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "Pipeline target unreachable.\n";
            return false;
        }

        if (!initializeSessionKey()) return false;

        std::ifstream infile(targetPath, std::ios::binary);
        if (!infile) {
            std::cerr << "File system extraction error.\n";
            return false;
        }

        infile.seekg(0, std::ios::end);
        long long totalSize = infile.tellg();
        infile.seekg(0, std::ios::beg);

        std::cout << "Executing structural cryptographic data analysis...\n";
        unsigned long long generatedHash = CryptoEngine::calculateFNV1aHash(targetPath);

        FileMetadata meta{};
        strncpy(meta.filename, targetPath.c_str(), 255);
        meta.fileSize = totalSize;
        meta.fileHash = generatedHash;

        send(clientSocket, reinterpret_cast<char*>(&meta), sizeof(FileMetadata), 0);

        long long resumeOffset = 0;
        recv(clientSocket, reinterpret_cast<char*>(&resumeOffset), sizeof(resumeOffset), 0);

        if (resumeOffset > 0) {
            std::cout << "Resuming file transfer from checkpoint offset index: " << resumeOffset << "\n";
            infile.seekg(resumeOffset, std::ios::beg);
        } else {
            std::cout << "Starting fresh secured file transfer sequence for: " << targetPath << "\n";
        }

        char buffer[65536];
        long long totalSent = resumeOffset;

        while (true) {
            infile.read(buffer, sizeof(buffer));
            int bytesRead = static_cast<int>(infile.gcount());
            if (bytesRead == 0) break;

            CryptoEngine::transformBuffer(buffer, bytesRead, secretKey);

            if (send(clientSocket, buffer, bytesRead, 0) == SOCKET_ERROR) {
                std::cout << "\nConnection dropped! Run the client again to resume.\n";
                break;
            }

            totalSent += bytesRead;
            renderProgressBar(totalSent, totalSize);
        }

        if (totalSent == totalSize) {
            std::cout << "\n\nSecure transmission complete.\n";
        }

        infile.close();
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage configuration mismatch: .\\client.exe <filename>\n";
        return 1;
    }

    SecureClient client(argv[1]);
    client.ConnectAndTransmit("127.0.0.1", 8080);
    return 0;
}