#ifndef XBANNER_GRABBER_HPP
#define XBANNER_GRABBER_HPP

#include <string>
#include <vector>
#include <map>
#include <regex>
#include <functional>
#include <ostream>           // Added for std::ostream in writeCSVRow
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

// Forward declarations of structures
struct TCPProbe;
struct UDPProbe;
struct ServiceInfo;

// BannerGrabber class declaration
class BannerGrabber {
public:
    // Constructor and Destructor
    BannerGrabber();
    ~BannerGrabber();

    // Public methods
    ServiceInfo grabBanner(const std::string& ip, int port, const std::string& protocol);
    ServiceInfo grabTCPBanner(const std::string& ip, int port);
    ServiceInfo grabUDPBanner(const std::string& ip, int port);
    ServiceInfo detectService(const std::string& ip, int port);
    void fingerprint(ServiceInfo& info);
    void scanRange(const std::string& ip, int startPort, int endPort, int threads, std::vector<ServiceInfo>& results);
    std::string getTLSDetails(const std::string& ip, int port);
    static void writeToCSV(const std::string& ip, const std::vector<ServiceInfo>& results, const std::string& filename); // Added

private:
    // Private helper methods
    std::string getCertificateInfo(SSL* ssl);
    std::string hexDump(const std::vector<unsigned char>& data, bool showAscii);
    std::map<std::string, std::string> parseHTTPHeaders(const std::string& httpResponse);
    static std::string serializeDetails(const std::map<std::string, std::string>& details); // Added
    static void writeCSVRow(std::ostream& os, const std::vector<std::string>& fields);      // Added
};

// Structure for TCP probes
struct TCPProbe {
    std::string initialProbe;         // Initial probe string to send
    std::string fallbackProbe;        // Fallback probe if initial fails
    int responseTimeout;              // Timeout for response in seconds
    std::string description;          // Description of the probe
    std::regex servicePattern;        // Regex pattern to identify service
};

// Structure for UDP probes
struct UDPProbe {
    std::vector<unsigned char> probeData;           // Data to send in UDP probe
    int responseTimeout;                            // Timeout for response in seconds
    std::string description;                        // Description of the probe
    std::function<std::string(const std::vector<unsigned char>&)> responseParser; // Function to parse UDP response
};

// Structure to hold service information
struct ServiceInfo {
    int port;                             // Port number
    std::string protocol;                 // Protocol (e.g., "TCP", "UDP")
    std::string status;                   // Status (e.g., "open", "closed", "filtered")
    std::string service;                  // Detected service name
    std::string version;                  // Service version
    std::string banner;                   // Raw banner response
    std::string certInfo;                 // TLS certificate information (if applicable)
    std::map<std::string, std::string> serviceDetails; // Additional service-specific details
};

// External probe maps (defined in the implementation file)
extern std::map<int, TCPProbe> tcpProbes;
extern std::map<int, UDPProbe> udpProbes;

#endif // XBANNER_GRABBER_HPP