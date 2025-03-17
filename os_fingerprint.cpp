#include "os_fingerprint.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <cstring>
#include <map>
#include <set>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

// Initialize static mutex
std::mutex OSFingerprintScanner::csvMutex;

// Custom TCP header
struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct ScanResult {
    bool rst_received;
    bool syn_ack_received;
    int response_time_ms;
    int ttl;
    int window_size;
};

struct OSSignature {
    std::string name;
    bool fin_rst;
    bool null_rst;
    bool xmas_rst;
    int typical_ttl;
    int window_size;
};

std::vector<OSSignature> knownSignatures = {
    {"Windows", true, true, true, 128, 8192},
    {"Windows 10/11", true, true, true, 128, 64240},
    {"Windows 7/8", true, true, true, 128, 8192},
    {"Windows Server", true, true, true, 128, 16384},
    {"Linux", false, false, false, 64, 5840},
    {"Ubuntu Linux", false, false, false, 64, 29200},
    {"CentOS/RHEL", false, false, false, 64, 14600},
    {"macOS", false, false, false, 64, 65535},
    {"Cisco IOS", true, true, true, 255, 4128},
    {"Juniper", false, false, false, 255, 16384}
};

uint16_t tcp_checksum(uint32_t src_addr, uint32_t dst_addr, uint8_t* tcp_segment, size_t length) {
    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } psh;
    psh.source_address = src_addr;
    psh.dest_address = dst_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(length);

    char* extended_header = new char[sizeof(pseudo_header) + length];
    memcpy(extended_header, &psh, sizeof(pseudo_header));
    memcpy(extended_header + sizeof(pseudo_header), tcp_segment, length);

    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)extended_header;
    for (size_t i = 0; i < (sizeof(pseudo_header) + length) / 2; i++) {
        sum += *ptr++;
    }
    if ((sizeof(pseudo_header) + length) % 2 != 0) {
        sum += *((uint8_t*)extended_header + sizeof(pseudo_header) + length - 1);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    delete[] extended_header;
    return ~sum;
}

ScanResult performScan(const std::string& ip, int port, int scan_type, int timeout_ms) {
    ScanResult result = {false, false, -1, -1, -1};
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        std::cerr << "Failed to create raw socket: " << strerror(errno) << std::endl;
        return result;
    }
    
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Failed to set IP_HDRINCL: " << strerror(errno) << std::endl;
        close(sockfd);
        return result;
    }
    
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &dest.sin_addr) <= 0) {
        std::cerr << "Invalid IP address: " << ip << std::endl;
        close(sockfd);
        return result;
    }
    
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sock < 0) {
        close(sockfd);
        return result;
    }
    dest.sin_port = htons(80);
    if (connect(temp_sock, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        close(temp_sock);
        close(sockfd);
        return result;
    }
    if (getsockname(temp_sock, (struct sockaddr*)&local_addr, &addr_len) < 0) {
        close(temp_sock);
        close(sockfd);
        return result;
    }
    close(temp_sock);
    
    char packet[4096];
    memset(packet, 0, sizeof(packet));
    struct iphdr* ipptr = (struct iphdr*)packet;
    ipptr->version = 4;
    ipptr->ihl = 5;
    ipptr->tos = 0;
    ipptr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcp_header));
    ipptr->id = htons(rand() % 65535);
    ipptr->frag_off = 0;
    ipptr->ttl = 64;
    ipptr->protocol = IPPROTO_TCP;
    ipptr->check = 0;
    ipptr->saddr = local_addr.sin_addr.s_addr;
    ipptr->daddr = dest.sin_addr.s_addr;
    
    struct tcp_header* tcp = (struct tcp_header*)(packet + sizeof(struct iphdr));
    tcp->source = htons(12345 + (rand() % 40000));
    tcp->dest = htons(port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->res1 = 0;
    tcp->fin = (scan_type == OSFingerprintScanner::OS_FINGERPRINT_FIN_SCAN);
    tcp->syn = 0;
    tcp->rst = 0;
    tcp->psh = (scan_type == OSFingerprintScanner::OS_FINGERPRINT_XMAS_SCAN);
    tcp->ack = 0;
    tcp->urg = (scan_type == OSFingerprintScanner::OS_FINGERPRINT_XMAS_SCAN);
    tcp->ece = 0;
    tcp->cwr = 0;
    tcp->window = htons(5840);
    tcp->check = 0;
    tcp->urg_ptr = 0;
    
    tcp->check = tcp_checksum(ipptr->saddr, ipptr->daddr, (uint8_t*)tcp, sizeof(struct tcp_header));
    
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcp_header), 0, 
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        close(sockfd);
        return result;
    }
    
    auto start_time = std::chrono::steady_clock::now();
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    if (poll(&pfd, 1, timeout_ms) > 0 && (pfd.revents & POLLIN)) {
        char buffer[4096];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        int received = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromlen);
        if (received > 0) {
            auto end_time = std::chrono::steady_clock::now();
            result.response_time_ms = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
            struct iphdr* resp_ip = (struct iphdr*)buffer;
            struct tcp_header* resp_tcp = (struct tcp_header*)(buffer + (resp_ip->ihl * 4));
            if (from.sin_addr.s_addr == dest.sin_addr.s_addr && 
                ntohs(resp_tcp->source) == port && 
                ntohs(resp_tcp->dest) == ntohs(tcp->source)) {
                result.rst_received = resp_tcp->rst;
                result.syn_ack_received = resp_tcp->syn && resp_tcp->ack;
                result.ttl = resp_ip->ttl;
                result.window_size = ntohs(resp_tcp->window);
            }
        }
    }
    
    close(sockfd);
    return result;
}

OSFingerprintScanner::OSFingerprintScanner(const std::string& csv_file) : csv_file_(csv_file) {
    std::lock_guard<std::mutex> lock(csvMutex);
    std::ifstream check_file(csv_file_);
    if (!check_file) {
        std::ofstream new_file(csv_file_);
        if (new_file) {
            new_file << "timestamp,target_ip,detected_os,confidence,fin_rst,null_rst,xmas_rst,ttl,window_size" << std::endl;
        }
        new_file.close();
    }
    check_file.close();
}

OSFingerprint OSFingerprintScanner::detectOS(const std::string& ip, int testPort) {
    OSFingerprint fingerprint;
    fingerprint.target_ip = ip;
    if (testPort <= 0 || testPort > 65535) testPort = 80;
    
    std::cout << "Performing OS detection on " << ip << " (port " << testPort << ")..." << std::endl;
    
    ScanResult fin_result = performScan(ip, testPort, OS_FINGERPRINT_FIN_SCAN, 2000);
    ScanResult null_result = performScan(ip, testPort, OS_FINGERPRINT_NULL_SCAN, 2000);
    ScanResult xmas_result = performScan(ip, testPort, OS_FINGERPRINT_XMAS_SCAN, 2000);
    
    fingerprint.fin_scan_rst = fin_result.rst_received;
    fingerprint.null_scan_rst = null_result.rst_received;
    fingerprint.xmas_scan_rst = xmas_result.rst_received;
    fingerprint.ttl = (fin_result.ttl > 0) ? fin_result.ttl : 
                     (null_result.ttl > 0 ? null_result.ttl : xmas_result.ttl);
    fingerprint.window_size = (fin_result.window_size > 0) ? fin_result.window_size : 
                             (null_result.window_size > 0 ? null_result.window_size : xmas_result.window_size);
    
    int best_match_score = 0;
    std::string best_match = "Unknown";
    for (const auto& sig : knownSignatures) {
        int score = 0;
        if (sig.fin_rst == fingerprint.fin_scan_rst) score += 4;
        if (sig.null_rst == fingerprint.null_scan_rst) score += 4;
        if (sig.xmas_rst == fingerprint.xmas_scan_rst) score += 4;
        if (fingerprint.ttl > 0) {
            int ttl_orig = (fingerprint.ttl <= 64) ? 64 : (fingerprint.ttl <= 128) ? 128 : 255;
            if (sig.typical_ttl == ttl_orig) score += 3;
        }
        if (fingerprint.window_size > 0 && sig.window_size > 0 && 
            std::abs(fingerprint.window_size - sig.window_size) < 1000) score += 2;
        if (score > best_match_score) {
            best_match_score = score;
            best_match = sig.name;
        }
    }
    
    fingerprint.os_name = (best_match_score < 8) ? "Unknown" : best_match;
    fingerprint.confidence = (best_match_score < 8) ? 0 : (best_match_score * 100) / 17;
    
    logToCSV(fingerprint);
    return fingerprint;
}

void OSFingerprintScanner::logToCSV(const OSFingerprint& fingerprint) {
    std::lock_guard<std::mutex> lock(csvMutex);
    std::ofstream file(csv_file_, std::ios::app);
    if (!file) {
        std::cerr << "Failed to open CSV file: " << csv_file_ << std::endl;
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    char timestamp[30];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&time_t_now));
    
    file << timestamp << ","
         << fingerprint.target_ip << ","
         << fingerprint.os_name << ","
         << fingerprint.confidence << ","
         << (fingerprint.fin_scan_rst ? "true" : "false") << ","
         << (fingerprint.null_scan_rst ? "true" : "false") << ","
         << (fingerprint.xmas_scan_rst ? "true" : "false") << ","
         << fingerprint.ttl << ","
         << fingerprint.window_size << std::endl;
    file.close();
}

std::map<std::string, OSFingerprint> OSFingerprintScanner::batchScan(const std::vector<std::string>& ips, int testPort) {
    std::map<std::string, OSFingerprint> results;
    for (const auto& ip : ips) {
        results[ip] = detectOS(ip, testPort);
    }
    return results;
}