#include <iostream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include <cctype>
#include <string>

// Windows Network Headers
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h> // Required for SIO_RCVALL (Promiscuous Mode flag)

// Explicitly link the Winsock library for compilers that support pragmas
#pragma comment(lib, "ws2_32.lib")

#define MAX_PACKET_SIZE 65536

// --- Manual Header Definitions ---

struct IPv4Header {
    uint8_t  v_ihl;        // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t  tos;          // Type of Service
    uint16_t total_length; // Total Length of the packet
    uint16_t id;           // Identification
    uint16_t frag_offset;  // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;          // Time to Live
    uint8_t  protocol;     // Protocol (e.g., 6 for TCP)
    uint16_t checksum;     // Header Checksum
    uint32_t src_ip;       // Source IP Address
    uint32_t dst_ip;       // Destination IP Address
};

struct TCPHeader {
    uint16_t src_port;             // Source Port
    uint16_t dst_port;             // Destination Port
    uint32_t seq_num;              // Sequence Number
    uint32_t ack_num;              // Acknowledgment Number
    uint8_t  data_offset_reserved; // Data Offset (4 bits) + Reserved (4 bits)
    uint8_t  flags;                // TCP Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    uint16_t window_size;          // Window Size
    uint16_t checksum;             // Checksum
    uint16_t urg_ptr;              // Urgent Pointer
};

// --- Formatting Helper Functions ---

// Convert a 32-bit integer IP into human-readable string format
std::string ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
    return std::string(ipStr);
}

// Generate annotated hex/ASCII dump of raw payloads
void printHexDump(const uint8_t* buffer, size_t size) {
    if (size == 0) {
        std::cout << "   [ No Payload Data ]" << std::endl;
        return;
    }

    for (size_t i = 0; i < size; i += 16) {
        // Print current memory offset line
        std::cout << "  0x" << std::setw(4) << std::setfill('0') << std::hex << i << "  ";

        // Hex section representation
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size) {
                std::cout << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i + j]) << " ";
            } else {
                std::cout << "   "; // Match layout alignment for trailing fragments
            }
        }

        std::cout << " ";

        // Printable character ASCII section representation
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size) {
                char ch = static_cast<char>(buffer[i + j]);
                std::cout << (std::isprint(static_cast<unsigned char>(ch)) ? ch : '.');
            }
        }
        std::cout << std::endl;
    }
    std::cout << std::dec << std::setfill(' ') << std::endl; // Restore stream state
}

// --- Main Execution ---

int main() {
    std::cout << "==================================================" << std::endl;
    std::cout << "     Winsock2 Raw TCP Sniffer & Hex Analyzer      " << std::endl;
    std::cout << "==================================================" << std::endl;

    // 1. Initialize Winsock subsystems
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[-] Winsock initialization failed. Error Code: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // 2. Resolve local hostname interface to bind the Sniffer
    char hostName[256];
    if (gethostname(hostName, sizeof(hostName)) == SOCKET_ERROR) {
        std::cerr << "[-] Failed to fetch hostname. Error Code: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_INET; // IPv4
    if (getaddrinfo(hostName, nullptr, &hints, &res) != 0 || res == nullptr) {
        std::cerr << "[-] Failed to resolve local IP configuration interface." << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in localInterface = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
    freeaddrinfo(res);

    std::cout << "[+] Sniffing Interface Active: " << ipToString(localInterface.sin_addr.s_addr) << std::endl;

    // 3. Create raw socket bound to the IP Protocol level
    SOCKET snifferSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (snifferSocket == INVALID_SOCKET) {
        std::cerr << "[-] Socket creation failed. Ensure you are running as ADMINISTRATOR. Error: "
                  << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Bind the socket to the chosen physical network interface card
    if (bind(snifferSocket, reinterpret_cast<sockaddr*>(&localInterface), sizeof(localInterface)) == SOCKET_ERROR) {
        std::cerr << "[-] Interface binding failed. Error Code: " << WSAGetLastError() << std::endl;
        closesocket(snifferSocket);
        WSACleanup();
        return 1;
    }

    // 4. Force Promiscuous Mode setting via IO Control commands
    unsigned long flag = 1;
    DWORD bytesReturned = 0;
    if (WSAIoctl(snifferSocket, SIO_RCVALL, &flag, sizeof(flag), nullptr, 0, &bytesReturned, nullptr, nullptr) == SOCKET_ERROR) {
        std::cerr << "[-] Promiscuous Mode (SIO_RCVALL) entry rejected. Error Code: " << WSAGetLastError() << std::endl;
        closesocket(snifferSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[+] Promiscuous Mode engaged successfully. Capturing stream...\n" << std::endl;

    // 5. Raw Packet Processing Loop
    std::vector<uint8_t> packetBuffer(MAX_PACKET_SIZE);
    int packetCount = 0;

    while (true) {
        int packetBytes = recv(snifferSocket, reinterpret_cast<char*>(packetBuffer.data()), MAX_PACKET_SIZE, 0);
        if (packetBytes <= 0) {
            std::cerr << "[-] Connection drop or drop telemetry encountered. Continuing loop..." << std::endl;
            continue;
        }

        // Parse Layer 3 (IPv4 Header)
        auto* ipHeader = reinterpret_cast<IPv4Header*>(packetBuffer.data());

        // Extract IP Header Length using bitwise masking (bottom 4 bits of v_ihl multiplied by 32-bit words)
        uint32_t ipHeaderLength = (ipHeader->v_ihl & 0x0F) * 4;

        // Filter and inspect TCP packets exclusively (Protocol ID: 6)
        if (ipHeader->protocol == 6) {
            packetCount++;

            // Move pointer boundary forward over the variable-length IP Header
            auto* tcpHeader = reinterpret_cast<TCPHeader*>(packetBuffer.data() + ipHeaderLength);

            // Extract TCP Header Length using bitwise operations (top 4 bits of data_offset_reserved)
            uint32_t tcpHeaderLength = ((tcpHeader->data_offset_reserved >> 4) & 0x0F) * 4;

            // Compute structural payload offsets
            uint32_t combinedHeaderLength = ipHeaderLength + tcpHeaderLength;
            int payloadSize = packetBytes - combinedHeaderLength;
            uint8_t* payloadData = packetBuffer.data() + combinedHeaderLength;

            // Print Field Annotations
            std::cout << "--------------------------------------------------" << std::endl;
            std::cout << "[#" << packetCount << "] TCP Packet Intercepted (" << packetBytes << " bytes)" << std::endl;
            std::cout << "--------------------------------------------------" << std::endl;
            std::cout << "  [IP LAYER]  Source IP:      " << ipToString(ipHeader->src_ip) << std::endl;
            std::cout << "              Destination IP: " << ipToString(ipHeader->dst_ip) << std::endl;
            std::cout << "              TTL Val:        " << static_cast<int>(ipHeader->ttl) << std::endl;
            std::cout << "  [TCP LAYER] Source Port:    " << ntohs(tcpHeader->src_port) << std::endl;
            std::cout << "              Dest Port:      " << ntohs(tcpHeader->dst_port) << std::endl;
            std::cout << "              Seq ID:         " << ntohl(tcpHeader->seq_num) << std::endl;
            std::cout << "              Ack ID:         " << ntohl(tcpHeader->ack_num) << std::endl;
            std::cout << "              Flags Hex:      0x" << std::hex << static_cast<int>(tcpHeader->flags) << std::dec << std::endl;
            std::cout << "  [PAYLOAD]   Data Size:      " << payloadSize << " bytes" << std::endl;
            std::cout << "  [HEX ANALYSIS]" << std::endl;

            // Print Field Annotated Hex Dump
            printHexDump(payloadData, (payloadSize > 0) ? static_cast<size_t>(payloadSize) : 0);
        }
    }

    // Clean up resources (unreachable code in standard infinite loops, kept for structural accuracy)
    closesocket(snifferSocket);
    WSACleanup();
    return 0;
}