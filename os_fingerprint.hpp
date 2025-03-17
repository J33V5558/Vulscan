#ifndef OS_FINGERPRINT_HPP
#define OS_FINGERPRINT_HPP

#include <string>
#include <vector>
#include <map>
#include <mutex>

struct OSFingerprint {
    std::string target_ip;
    std::string os_name;
    int confidence;
    bool fin_scan_rst;
    bool null_scan_rst;
    bool xmas_scan_rst;
    int ttl;
    int window_size;
};

class OSFingerprintScanner {
public:
    OSFingerprintScanner(const std::string& csv_file = "os_fingerprints.csv");
    OSFingerprint detectOS(const std::string& ip, int testPort = 80);
    std::map<std::string, OSFingerprint> batchScan(const std::vector<std::string>& ips, int testPort = 80);

    static const int OS_FINGERPRINT_FIN_SCAN = 1;
    static const int OS_FINGERPRINT_NULL_SCAN = 2;
    static const int OS_FINGERPRINT_XMAS_SCAN = 3;

private:
    std::string csv_file_;
    static std::mutex csvMutex; // Added for thread safety

    void logToCSV(const OSFingerprint& fingerprint);
};

#endif // OS_FINGERPRINT_HPP