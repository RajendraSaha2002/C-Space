#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define PORT 8080

int main()
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return -1;
    }
    SOCKET sock = INVALID_SOCKET;
#else
    int sock = 0;
#endif

    struct sockaddr_in serv_addr;
    const char *hello = "Hello from client";

#ifdef _WIN32
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return -1;
    }
#else
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        std::cerr << "Socket creation failed" << std::endl;
        return -1;
    }
#endif

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

#ifdef _WIN32
    // Use inet_addr on Windows for IPv4 literal (InetPtonA may be unavailable on some SDKs)
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (serv_addr.sin_addr.s_addr == INADDR_NONE) {
        std::cerr << "Invalid address" << std::endl;
        closesocket(sock);
        WSACleanup();
        return -1;
    }
#else
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid address" << std::endl;
        close(sock);
        return -1;
    }
#endif

#ifdef _WIN32
    if (connect(sock, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) == SOCKET_ERROR)
    {
        std::cerr << "Connection Failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    int sent = send(sock, hello, static_cast<int>(strlen(hello)), 0);
    if (sent == SOCKET_ERROR) {
        std::cerr << "Send failed: " << WSAGetLastError() << std::endl;
    } else {
        std::cout << "Message sent" << std::endl;
    }
    closesocket(sock);
    WSACleanup();
#else
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cerr << "Connection Failed" << std::endl;
        close(sock);
        return -1;
    }
    send(sock, hello, strlen(hello), 0);
    std::cout << "Message sent" << std::endl;
    close(sock);
#endif

    return 0;
}