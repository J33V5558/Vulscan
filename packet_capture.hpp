#ifndef PACKET_CAPTURE_HPP
#define PACKET_CAPTURE_HPP

#include <string>
#include <vector>
#include <mutex>
#include <pcap/pcap.h>

struct PacketInfo {
    std::string timestamp;
    std::string sourceIP;
    std::string destIP;
    int sourcePort;
    int destPort;
    std::string protocol;
    int packetLength;
    std::vector<unsigned char> payload;
};

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();
    bool initialize(const std::string& interface, const std::string& filter);
    bool startCapture(int packetCount);
    bool captureFromFile(const std::string& filename);
    void stopCapture();
    bool saveToCSV(const std::string& filename);
    std::vector<std::string> getNetworkInterfaces();
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    pcap_t* handle;

private:
    
    char errbuf[PCAP_ERRBUF_SIZE];
    bool running;
    std::vector<PacketInfo> packets;
    static std::mutex csvMutex; // Added for thread safety

    void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
};

#endif // PACKET_CAPTURE_HPP