#include "packet_capture.hpp"
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

// Initialize static mutex
std::mutex PacketCapture::csvMutex;

PacketCapture::PacketCapture() : handle(nullptr), running(false) {
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
}

PacketCapture::~PacketCapture() {
    if (handle) pcap_close(handle);
}

bool PacketCapture::initialize(const std::string& interface, const std::string& filter) {
    std::string dev;
    if (interface.empty()) {
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cerr << "Error finding devices: " << errbuf << std::endl;
            return false;
        }
        if (alldevs == nullptr) {
            std::cerr << "No devices found" << std::endl;
            pcap_freealldevs(alldevs);
            return false;
        }
        dev = alldevs->name;
        pcap_freealldevs(alldevs);
    } else {
        dev = interface;
    }
    
    handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device: " << dev << ": " << errbuf << std::endl;
        return false;
    }
    
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        std::cerr << "Error setting non-blocking mode: " << errbuf << std::endl;
        pcap_close(handle);
        handle = nullptr;
        return false;
    }
    
    if (!filter.empty()) {
        struct bpf_program fp;
        bpf_u_int32 net = 0;
        if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
            std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            handle = nullptr;
            return false;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            handle = nullptr;
            return false;
        }
        pcap_freecode(&fp);
    }
    
    return true;
}

bool PacketCapture::startCapture(int packetCount) {
    if (!handle) {
        std::cerr << "Packet capture not initialized" << std::endl;
        return false;
    }
    
    running = true;
    int capturedPackets = 0;
    
    while (running && (packetCount == -1 || capturedPackets < packetCount)) {
        struct pcap_pkthdr header;
        const u_char* packet = pcap_next(handle, &header);
        if (packet) {
            processPacket(&header, packet);
            capturedPackets++;
        }
    }
    
    return true;
}

bool PacketCapture::captureFromFile(const std::string& filename) {
    if (handle) pcap_close(handle);
    
    handle = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return false;
    }
    
    struct pcap_pkthdr header;
    const u_char* packet;
    while ((packet = pcap_next(handle, &header)) != nullptr) {
        processPacket(&header, packet);
    }
    
    return true;
}

void PacketCapture::stopCapture() {
    running = false;
}

bool PacketCapture::saveToCSV(const std::string& filename) {
    std::lock_guard<std::mutex> lock(csvMutex);
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return false;
    }
    
    file << "Timestamp,Source IP,Destination IP,Source Port,Destination Port,Protocol,Packet Length,Payload\n";
    for (const auto& packet : packets) {
        file << packet.timestamp << ","
             << packet.sourceIP << ","
             << packet.destIP << ","
             << packet.sourcePort << ","
             << packet.destPort << ","
             << packet.protocol << ","
             << packet.packetLength << ",";
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char byte : packet.payload) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        file << "\"" << ss.str() << "\"\n";
    }
    
    file.close();
    return true;
}

std::vector<std::string> PacketCapture::getNetworkInterfaces() {
    std::vector<std::string> interfaces;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return interfaces;
    }
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        interfaces.push_back(dev->name);
    }
    pcap_freealldevs(alldevs);
    return interfaces;
}

void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(userData);
    capture->processPacket(pkthdr, packet);
}

void PacketCapture::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketInfo info;
    char timestr[64];
    time_t local_tv_sec = pkthdr->ts.tv_sec;
    struct tm* ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ltime);
    info.timestamp = timestr;
    info.packetLength = pkthdr->len;
    
    const struct ether_header* etherHeader = reinterpret_cast<const struct ether_header*>(packet);
    if (ntohs(etherHeader->ether_type) == ETHERTYPE_IP) {
        const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
        char sourceIP[INET_ADDRSTRLEN];
        char destIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
        info.sourceIP = sourceIP;
        info.destIP = destIP;
        
        int ipHeaderLen = ipHeader->ip_hl * 4;
        if (ipHeader->ip_p == IPPROTO_TCP) {
            const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(
                packet + sizeof(struct ether_header) + ipHeaderLen);
            info.sourcePort = ntohs(tcpHeader->th_sport);
            info.destPort = ntohs(tcpHeader->th_dport);
            info.protocol = "TCP";
            int tcpHeaderLen = tcpHeader->th_off * 4;
            const u_char* payload = packet + sizeof(struct ether_header) + ipHeaderLen + tcpHeaderLen;
            int payloadLen = pkthdr->len - (sizeof(struct ether_header) + ipHeaderLen + tcpHeaderLen);
            if (payloadLen > 0) {
                info.payload.assign(payload, payload + payloadLen);
            }
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            const struct udphdr* udpHeader = reinterpret_cast<const struct udphdr*>(
                packet + sizeof(struct ether_header) + ipHeaderLen);
            info.sourcePort = ntohs(udpHeader->uh_sport);
            info.destPort = ntohs(udpHeader->uh_dport);
            info.protocol = "UDP";
            const u_char* payload = packet + sizeof(struct ether_header) + ipHeaderLen + sizeof(struct udphdr);
            int payloadLen = pkthdr->len - (sizeof(struct ether_header) + ipHeaderLen + sizeof(struct udphdr));
            if (payloadLen > 0) {
                info.payload.assign(payload, payload + payloadLen);
            }
        } else {
            info.sourcePort = 0;
            info.destPort = 0;
            info.protocol = "Other";
            const u_char* payload = packet + sizeof(struct ether_header) + ipHeaderLen;
            int payloadLen = pkthdr->len - (sizeof(struct ether_header) + ipHeaderLen);
            if (payloadLen > 0) {
                info.payload.assign(payload, payload + payloadLen);
            }
        }
        packets.push_back(info);
    }
}