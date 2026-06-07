#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>
#include <iostream>
#include <cstdlib>

#pragma comment(lib, "Ws2_32.lib")

#define PORT 8080

int main()
{
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    SOCKET server_fd = INVALID_SOCKET;
    SOCKET new_socket = INVALID_SOCKET;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == INVALID_SOCKET)
    {
        std::cerr << "socket failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Note: On Windows SO_REUSEADDR semantics differ from POSIX but this is kept for parity.
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR)
    {
        std::cerr << "setsockopt failed: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR)
    {
        std::cerr << "bind failed: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    if (listen(server_fd, 3) == SOCKET_ERROR)
    {
        std::cerr << "listen failed: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    if (new_socket == INVALID_SOCKET)
    {
        std::cerr << "accept failed: " << WSAGetLastError() << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    int valread = recv(new_socket, buffer, sizeof(buffer) - 1, 0);
    if (valread == SOCKET_ERROR) {
        std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
    } else {
        buffer[valread] = '\0';
        std::cout << "Message from client:" << buffer << std::endl;
    }

    closesocket(new_socket);
    closesocket(server_fd);
    WSACleanup();
    return 0;
}