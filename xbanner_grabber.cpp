#include "xbanner_grabber.hpp"
#include <iostream>
#include <map>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <thread>
#include <mutex>
#include <chrono>
#include <string>
#include <regex>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <fcntl.h>
#include <cctype>
#include <fstream>


BannerGrabber::BannerGrabber() {
}

BannerGrabber::~BannerGrabber() {
}


std::map<int, TCPProbe> tcpProbes = {
    {21, {"HELP\r\n", "SYST\r\n", 3, "FTP", 
          std::regex("(FTP|ftp|File Transfer Protocol|FileZilla|vsFTPd|ProFTPD|Pure-FTPd).*")}},
    {22, {"SSH-2.0-Scanner\r\n", "", 2, "SSH", 
          std::regex("(SSH|ssh|OpenSSH|libssh).*")}},
    {23, {"\r\n", "\x03\x1b[A", 2, "Telnet", 
          std::regex("(Telnet|telnet|login:|Username:|Password:).*")}},
    {25, {"EHLO scanner.local\r\n", "HELO scanner.local\r\n", 3, "SMTP", 
          std::regex("(SMTP|smtp|mail|postfix|exim|sendmail).*")}},
    {80, {"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 Scanner\r\nAccept: */*\r\n\r\n", 
          "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n", 3, "HTTP", 
          std::regex("(HTTP|http|Apache|nginx|IIS|Express|Tomcat|WebServer).*")}},
    {443, {"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 Scanner\r\nAccept: */*\r\n\r\n", 
           "", 3, "HTTPS", 
           std::regex("(HTTP|http|TLS|SSL|Apache|nginx|IIS|Express|Certificate).*")}},
    {110, {"USER test\r\n", "CAPA\r\n", 3, "POP3", 
           std::regex("(POP3|pop3|\\+OK).*")}},
    {143, {"a001 CAPABILITY\r\n", "a002 LOGIN SCAN SCAN\r\n", 3, "IMAP", 
           std::regex("(IMAP|imap|\\* OK).*")}},
    {3306, {"\x10\x00\x00\x00\x85\xae\x03\x00\x00\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 
            "", 2, "MySQL", 
            std::regex("(MySQL|mysql|MariaDB|maria|\\x0a[0-9]\\.[0-9]\\.[0-9]).*")}},
    {5432, {"\x00\x00\x00\x08\x00\x00\x00\x00", 
            "", 2, "PostgreSQL", 
            std::regex("(PostgreSQL|postgres).*")}},
    {27017, {"\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00", 
             "", 2, "MongoDB", 
             std::regex("(MongoDB|mongo).*")}},
    {6379, {"PING\r\n", "INFO\r\n", 2, "Redis", 
            std::regex("(Redis|redis|PONG).*")}},
    {8080, {"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 Scanner\r\nAccept: */*\r\n\r\n", 
            "", 3, "HTTP Alternate", 
            std::regex("(HTTP|http|Apache|nginx|IIS|Express|Tomcat|WebServer).*")}},
    {9200, {"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", 
            "", 3, "Elasticsearch", 
            std::regex("(elasticsearch|Elasticsearch|\"version\":\\{\"number\":).*")}},
    {11211, {"stats\r\n", "version\r\n", 2, "Memcached", 
             std::regex("(Memcached|memcached|STAT).*")}}
};

// UDP probes with specialized parsers
std::map<int, UDPProbe> udpProbes = {
    {53, {
        {0xAA, 0xAA, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
         0x03, 'c', 'o', 'm', 0x00,
         0x00, 0x01, 0x00, 0x01},
        3,
        "DNS",
        [](const std::vector<unsigned char>& response) -> std::string {
            if (response.size() < 12) return "Malformed DNS response";
            std::stringstream ss;
            ss << "DNS Server: ";
            int rcode = response[3] & 0x0F;
            switch (rcode) {
                case 0: ss << "NOERROR"; break;
                case 1: ss << "FORMERR"; break;
                case 2: ss << "SERVFAIL"; break;
                case 3: ss << "NXDOMAIN"; break;
                case 5: ss << "REFUSED"; break;
                default: ss << "Code " << rcode; break;
            }
            bool aa = (response[2] & 0x04) != 0;
            if (aa) ss << " (Authoritative)";
            bool ra = (response[3] & 0x80) != 0;
            ss << (ra ? " (Recursion Available)" : " (No Recursion)");
            return ss.str();
        }
    }},
    {161, {
        {0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
         0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02,
         0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02,
         0x01, 0x05, 0x00},
        3,
        "SNMP",
        [](const std::vector<unsigned char>& response) -> std::string {
            std::stringstream ss;
            ss << "SNMP Service: ";
            if (response.size() > 2 && response[0] == 0x30) {
                ss << "v1/v2c Detected";
                for (size_t i = 1; i < response.size() - 8; i++) {
                    if (response[i] == 0x04 && response[i+1] < 64) {
                        ss << " (Community: ";
                        int len = response[i+1];
                        for (int j = 0; j < len && i+2+j < response.size(); j++) {
                            if (isprint(response[i+2+j]))
                                ss << static_cast<char>(response[i+2+j]);
                            else
                                ss << ".";
                        }
                        ss << ")";
                        break;
                    }
                }
            } else {
                ss << "Detected";
            }
            return ss.str();
        }
    }},
    {123, {
        {0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        3,
        "NTP",
        [](const std::vector<unsigned char>& response) -> std::string {
            if (response.size() < 4) return "Malformed NTP response";
            std::stringstream ss;
            ss << "NTP Server: ";
            int li = (response[0] >> 6) & 0x03;
            int vn = (response[0] >> 3) & 0x07;
            int mode = response[0] & 0x07;
            ss << "v" << vn;
            switch (mode) {
                case 1: ss << " (Symmetric Active)"; break;
                case 2: ss << " (Symmetric Passive)"; break;
                case 3: ss << " (Client)"; break;
                case 4: ss << " (Server)"; break;
                case 5: ss << " (Broadcast)"; break;
                case 6: ss << " (Control Message)"; break;
                default: ss << " (Unknown Mode)"; break;
            }
            if (response.size() >= 2) {
                int stratum = response[1];
                if (stratum == 0) ss << " (Unspecified)";
                else if (stratum == 1) ss << " (Primary)";
                else if (stratum <= 15) ss << " (Secondary)";
                else ss << " (Reserved)";
            }
            return ss.str();
        }
    }},
    {67, {
        {0x01, 0x01, 0x06, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0xff},
        5,
        "DHCP",
        [](const std::vector<unsigned char>& response) -> std::string {
            if (response.size() < 240) return "Malformed DHCP response";
            std::stringstream ss;
            ss << "DHCP Server: ";
            if (response[0] == 0x02) {
                ss << "Offer";
                if (response.size() >= 16) {
                    ss << " (Offered IP: " 
                       << static_cast<int>(response[16]) << "."
                       << static_cast<int>(response[17]) << "."
                       << static_cast<int>(response[18]) << "."
                       << static_cast<int>(response[19]) << ")";
                }
                for (size_t i = 240; i < response.size() - 6; i++) {
                    if (response[i] == 0x36 && response[i+1] == 0x04) {
                        ss << " (Server ID: "
                           << static_cast<int>(response[i+2]) << "."
                           << static_cast<int>(response[i+3]) << "."
                           << static_cast<int>(response[i+4]) << "."
                           << static_cast<int>(response[i+5]) << ")";
                        break;
                    }
                }
            } else {
                ss << "Detected";
            }
            return ss.str();
        }
    }},
    {5353, {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x05, '_', 'h', 't', 't', 'p', 0x04, '_', 't', 'c', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
         0x00, 0x0c, 0x00, 0x01},
        2,
        "mDNS",
        [](const std::vector<unsigned char>& response) -> std::string {
            if (response.size() < 12) return "Malformed mDNS response";
            std::stringstream ss;
            ss << "mDNS Service: ";
            if ((response[2] & 0x80) != 0) {
                ss << "Active";
                int answers = (response[6] << 8) | response[7];
                ss << " (" << answers << " answers)";
            } else {
                ss << "Detected";
            }
            return ss.str();
        }
    }}
};

// SSL/TLS context initialization
SSL_CTX* initializeSSLContext() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    return ctx;
}

std::string BannerGrabber::getCertificateInfo(SSL* ssl) {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) {
        return "No certificate available";
    }
    std::stringstream ss;
    ss << "Certificate: ";
    X509_NAME* subjectName = X509_get_subject_name(cert);
    if (subjectName != nullptr) {
        char commonName[256] = {0};
        int len = X509_NAME_get_text_by_NID(subjectName, NID_commonName, commonName, sizeof(commonName));
        if (len > 0) {
            if (len >= sizeof(commonName)) commonName[sizeof(commonName) - 1] = '\0';
            ss << "CN=" << commonName << ", ";
        }
    }
    X509_NAME* issuerName = X509_get_issuer_name(cert);
    if (issuerName != nullptr) {
        char issuerCommonName[256] = {0};
        int len = X509_NAME_get_text_by_NID(issuerName, NID_commonName, issuerCommonName, sizeof(issuerCommonName));
        if (len > 0) {
            if (len >= sizeof(issuerCommonName)) issuerCommonName[sizeof(issuerCommonName) - 1] = '\0';
            ss << "Issuer=" << issuerCommonName << ", ";
        }
    }
    ASN1_TIME* notBefore = X509_get_notBefore(cert);
    ASN1_TIME* notAfter = X509_get_notAfter(cert);
    if (notBefore != nullptr && notAfter != nullptr) {
        char validityBuffer[256];
        BIO* bio = BIO_new(BIO_s_mem());
        if (bio != nullptr) {
            ASN1_TIME_print(bio, notBefore);
            BIO_read(bio, validityBuffer, sizeof(validityBuffer) - 1);
            validityBuffer[sizeof(validityBuffer) - 1] = '\0';
            ss << "Valid from=" << validityBuffer << ", ";
            BIO_reset(bio);
            ASN1_TIME_print(bio, notAfter);
            BIO_read(bio, validityBuffer, sizeof(validityBuffer) - 1);
            validityBuffer[sizeof(validityBuffer) - 1] = '\0';
            ss << "Valid until=" << validityBuffer;
            BIO_free(bio);
        }
    }
    X509_free(cert);
    return ss.str();
}

ServiceInfo BannerGrabber::grabBanner(const std::string& ip, int port, const std::string& protocol) {
    ServiceInfo info;
    info.port = port;
    info.protocol = protocol;
    if (protocol == "TCP") {
        return grabTCPBanner(ip, port);
    } else if (protocol == "UDP") {
        return grabUDPBanner(ip, port);
    }
    info.status = "unknown";
    return info;
}

ServiceInfo BannerGrabber::grabTCPBanner(const std::string& ip, int port) {
    ServiceInfo info;
    info.port = port;
    info.protocol = "TCP";
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        info.status = "closed";
        return info;
    }
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr);
    int connectResult = connect(sock, (struct sockaddr*)&target, sizeof(target));
    if (connectResult < 0 && errno != EINPROGRESS) {
        close(sock);
        info.status = "closed";
        return info;
    }
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    if (select(sock + 1, NULL, &writefds, NULL, &tv) <= 0) {
        close(sock);
        info.status = "timeout";
        return info;
    }
    int optval = 0;
    socklen_t optlen = sizeof(optval);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0 || optval != 0) {
        close(sock);
        info.status = "closed";
        return info;
    }
    fcntl(sock, F_SETFL, flags);
    info.status = "open";
    std::string serviceName = "unknown";
    std::string banner = "";
    if (tcpProbes.count(port)) {
        const TCPProbe& probe = tcpProbes[port];
        serviceName = probe.description;
        struct timeval readTimeout;
        readTimeout.tv_sec = probe.responseTimeout;
        readTimeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &readTimeout, sizeof(readTimeout));
        if (port == 443 || port == 8443 || port == 465 || port == 993 || port == 995) {
            SSL_CTX* ctx = initializeSSLContext();
            if (ctx != nullptr) {
                SSL* ssl = SSL_new(ctx);
                if (ssl != nullptr) {
                    SSL_set_fd(ssl, sock);
                    SSL_set_connect_state(ssl);
                    int sslResult = SSL_connect(ssl);
                    if (sslResult == 1) {
                        info.version = SSL_get_version(ssl);
                        info.certInfo = getCertificateInfo(ssl);
                        if (!probe.initialProbe.empty()) {
                            SSL_write(ssl, probe.initialProbe.c_str(), probe.initialProbe.size());
                        }
                        char buffer[4096];
                        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                        if (bytes > 0) {
                            buffer[bytes] = '\0';
                            banner = std::string(buffer, bytes);
                        }
                    } else {
                        info.status = "error";
                        info.version = "SSL/TLS (handshake failed)";
                        info.banner = "SSL error: " + std::string(ERR_error_string(SSL_get_error(ssl, sslResult), nullptr));
                    }
                    SSL_free(ssl);
                } else {
                    info.status = "error";
                    info.banner = "Failed to create SSL object";
                }
                SSL_CTX_free(ctx);
            }
        } else {
            if (!probe.initialProbe.empty()) {
                send(sock, probe.initialProbe.c_str(), probe.initialProbe.size(), 0);
            }
            char buffer[4096];
            std::string fullBanner;
            int totalBytes = 0;
            int bytes;
            do {
                bytes = recv(sock, buffer, sizeof(buffer) - 1 - totalBytes, 0);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    fullBanner.append(buffer, bytes);
                    totalBytes += bytes;
                }
            } while (bytes > 0 && totalBytes < sizeof(buffer) - 1);
            if (totalBytes > 0) {
                banner = fullBanner;
            } else if (!probe.fallbackProbe.empty()) {
                send(sock, probe.fallbackProbe.c_str(), probe.fallbackProbe.size(), 0);
                totalBytes = 0;
                do {
                    bytes = recv(sock, buffer, sizeof(buffer) - 1 - totalBytes, 0);
                    if (bytes > 0) {
                        buffer[bytes] = '\0';
                        fullBanner.append(buffer, bytes);
                        totalBytes += bytes;
                    }
                } while (bytes > 0 && totalBytes < sizeof(buffer) - 1);
                if (totalBytes > 0) {
                    banner = fullBanner;
                }
            }
        }
        if (!banner.empty()) {
            std::smatch matches;
            if (std::regex_search(banner, matches, probe.servicePattern)) {
                if (matches.size() > 0) {
                    info.version = matches[0].str();
                }
            }
        }
    } else {
        const char* genericProbe = "GET / HTTP/1.0\r\n\r\n";
        send(sock, genericProbe, strlen(genericProbe), 0);
        char buffer[4096];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            banner = std::string(buffer, bytes);
        }
    }
    if (info.version.empty() && !banner.empty()) {
        std::istringstream iss(banner);
        std::string firstLine;
        std::getline(iss, firstLine);
        if (firstLine.length() > 100) {
            firstLine = firstLine.substr(0, 100) + "...";
        }
        info.version = firstLine;
    }
    if (banner.length() > 1024) {
        banner = banner.substr(0, 1024) + "...";
    }
    for (size_t i = 0; i < banner.length(); i++) {
        if (!isprint(static_cast<unsigned char>(banner[i])) && !isspace(static_cast<unsigned char>(banner[i]))) {
            banner[i] = '.';
        }
    }
    info.banner = banner;
    info.service = serviceName;
    close(sock);
    return info;
}

ServiceInfo BannerGrabber::grabUDPBanner(const std::string& ip, int port) {
    ServiceInfo info;
    info.port = port;
    info.protocol = "UDP";
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        info.status = "error";
        return info;
    }
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr);
    if (udpProbes.count(port)) {
        const UDPProbe& probe = udpProbes[port];
        info.service = probe.description;
        if (probe.responseTimeout > 0) {
            tv.tv_sec = probe.responseTimeout;
        }
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        sendto(sock, probe.probeData.data(), probe.probeData.size(), 0, 
               (struct sockaddr*)&target, sizeof(target));
        unsigned char buffer[4096];
        socklen_t len = sizeof(target);
        int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, 
                             (struct sockaddr*)&target, &len);
        if (bytes > 0) {
            info.status = "open";
            std::vector<unsigned char> response(buffer, buffer + bytes);
            if (probe.responseParser) {
                info.version = probe.responseParser(response);
            }
            std::stringstream ss;
            int printableChars = 0;
            for (int i = 0; i < bytes; i++) {
                if (isprint(buffer[i]) || isspace(buffer[i])) {
                    printableChars++;
                }
            }
            if (printableChars > bytes * 0.7) {
                ss << "ASCII: ";
                for (int i = 0; i < bytes && i < 200; i++) {
                    if (isprint(buffer[i]) || isspace(buffer[i])) {
                        ss << static_cast<char>(buffer[i]);
                    } else {
                        ss << '.';
                    }
                }
                if (bytes > 200) {
                    ss << "...";
                }
            }
            ss << "\nHEX: ";
            for (int i = 0; i < bytes && i < 50; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') 
                   << static_cast<int>(buffer[i]) << " ";
            }
            if (bytes > 50) {
                ss << "...";
            }
            info.banner = ss.str();
        } else {
            info.status = "filtered";
        }
    } else {
        const char* genericProbe = "HELP";
        sendto(sock, genericProbe, strlen(genericProbe), 0,
               (struct sockaddr*)&target, sizeof(target));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char buffer[4096];
        socklen_t len = sizeof(target);
        int bytes = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&target, &len);
        if (bytes > 0) {
            info.status = "open";
            buffer[bytes] = '\0';
            info.banner = std::string(buffer, bytes);
            info.service = "unknown";
        } else {
            info.status = "filtered";
        }
    }
    close(sock);
    return info;
}

std::string BannerGrabber::hexDump(const std::vector<unsigned char>& data, bool showAscii) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < data.size(); i++) {
        if (i % 16 == 0) {
            if (i > 0 && showAscii) {
                ss << "  ";
                for (size_t j = i - 16; j < i; j++) {
                    if (isprint(data[j])) {
                        ss << static_cast<char>(data[j]);
                    } else {
                        ss << '.';
                    }
                }
            }
            ss << "\n" << std::setw(4) << i << ": ";
        }
        ss << std::setw(2) << static_cast<int>(data[i]) << " ";
    }
    if (showAscii) {
        size_t remaining = data.size() % 16;
        if (remaining > 0) {
            for (size_t i = 0; i < (16 - remaining) * 3; i++) {
                ss << " ";
            }
            ss << "  ";
            for (size_t i = data.size() - remaining; i < data.size(); i++) {
                if (isprint(data[i])) {
                    ss << static_cast<char>(data[i]);
                } else {
                    ss << '.';
                }
            }
        }
    }
    return ss.str();
}

ServiceInfo BannerGrabber::detectService(const std::string& ip, int port) {
    ServiceInfo tcpInfo = grabTCPBanner(ip, port);
    if (tcpInfo.status == "open") {
        return tcpInfo;
    }
    ServiceInfo udpInfo = grabUDPBanner(ip, port);
    if (udpInfo.status == "open") {
        return udpInfo;
    }
    return tcpInfo;
}

void BannerGrabber::fingerprint(ServiceInfo& info) {
    if (info.service == "HTTP" || info.service == "HTTPS") {
        if (info.banner.find("Apache") != std::string::npos) {
            std::regex apacheVersion("Apache/([0-9]+\\.[0-9]+\\.[0-9]+)");
            std::smatch matches;
            if (std::regex_search(info.banner, matches, apacheVersion) && matches.size() > 1) {
                info.serviceDetails["Server"] = "Apache";
                info.serviceDetails["Version"] = matches[1].str();
            }
        } else if (info.banner.find("nginx") != std::string::npos) {
            std::regex nginxVersion("nginx/([0-9]+\\.[0-9]+\\.[0-9]+)");
            std::smatch matches;
            if (std::regex_search(info.banner, matches, nginxVersion) && matches.size() > 1) {
                info.serviceDetails["Server"] = "nginx";
                info.serviceDetails["Version"] = matches[1].str();
            }
        } else if (info.banner.find("Microsoft-IIS") != std::string::npos) {
            std::regex iisVersion("Microsoft-IIS/([0-9\\.]+)");
            std::smatch matches;
            if (std::regex_search(info.banner, matches, iisVersion) && matches.size() > 1) {
                info.serviceDetails["Server"] = "Microsoft IIS";
                info.serviceDetails["Version"] = matches[1].str();
            }
        }
        if (info.banner.find("PHP") != std::string::npos) {
            std::regex phpVersion("PHP/([0-9\\.]+)");
            std::smatch matches;
            if (std::regex_search(info.banner, matches, phpVersion) && matches.size() > 1) {
                info.serviceDetails["Framework"] = "PHP";
                info.serviceDetails["FrameworkVersion"] = matches[1].str();
            }
        } else if (info.banner.find("ASP.NET") != std::string::npos) {
            info.serviceDetails["Framework"] = "ASP.NET";
        }
        if (info.banner.find("WordPress") != std::string::npos) {
            info.serviceDetails["CMS"] = "WordPress";
        } else if (info.banner.find("Drupal") != std::string::npos) {
            info.serviceDetails["CMS"] = "Drupal";
        } else if (info.banner.find("Joomla") != std::string::npos) {
            info.serviceDetails["CMS"] = "Joomla";
        }
    } else if (info.service == "SSH") {
        std::regex sshVersion("SSH-([0-9\\.]+)-(.+)");
        std::smatch matches;
        if (std::regex_search(info.banner, matches, sshVersion) && matches.size() > 2) {
            info.serviceDetails["Protocol"] = "SSH " + matches[1].str();
            info.serviceDetails["Software"] = matches[2].str();
        }
    } else if (info.service == "FTP") {
        std::regex ftpVersion("([A-Za-z0-9\\-_]+) FTP ([A-Za-z0-9\\-_\\.]+)");
        std::smatch matches;
        if (std::regex_search(info.banner, matches, ftpVersion) && matches.size() > 2) {
            info.serviceDetails["Server"] = matches[1].str();
            info.serviceDetails["Version"] = matches[2].str();
        }
    } else if (info.service == "MySQL") {
        std::regex mysqlVersion("([0-9\\.]+)");
        std::smatch matches;
        if (std::regex_search(info.banner, matches, mysqlVersion) && matches.size() > 1) {
            info.serviceDetails["DBMS"] = "MySQL";
            info.serviceDetails["Version"] = matches[1].str();
        }
    } else if (info.service == "PostgreSQL") {
        std::regex pgVersion("PostgreSQL ([0-9\\.]+)");
        std::smatch matches;
        if (std::regex_search(info.banner, matches, pgVersion) && matches.size() > 1) {
            info.serviceDetails["DBMS"] = "PostgreSQL";
            info.serviceDetails["Version"] = matches[1].str();
        }
    }
    if (info.banner.find("Ubuntu") != std::string::npos) {
        info.serviceDetails["OS"] = "Ubuntu Linux";
    } else if (info.banner.find("Debian") != std::string::npos) {
        info.serviceDetails["OS"] = "Debian Linux";
    } else if (info.banner.find("CentOS") != std::string::npos) {
        info.serviceDetails["OS"] = "CentOS Linux";
    } else if (info.banner.find("Red Hat") != std::string::npos) {
        info.serviceDetails["OS"] = "Red Hat Linux";
    } else if (info.banner.find("Windows") != std::string::npos) {
        info.serviceDetails["OS"] = "Windows";
    } else if (info.banner.find("FreeBSD") != std::string::npos) {
        info.serviceDetails["OS"] = "FreeBSD";
    }
}

void BannerGrabber::scanRange(const std::string& ip, int startPort, int endPort, int threads, std::vector<ServiceInfo>& results) {
    std::vector<std::thread> threadPool;
    std::mutex resultsMutex;
    int portsPerThread = (endPort - startPort + 1) / threads;
    for (int i = 0; i < threads; i++) {
        int threadStartPort = startPort + (i * portsPerThread);
        int threadEndPort = (i == threads - 1) ? endPort : threadStartPort + portsPerThread - 1;
        threadPool.push_back(std::thread([this, ip, threadStartPort, threadEndPort, &resultsMutex, &results]() {
            for (int port = threadStartPort; port <= threadEndPort; port++) {
                ServiceInfo info = detectService(ip, port);
                if (info.status == "open") {
                    fingerprint(info);
                    std::lock_guard<std::mutex> lock(resultsMutex);
                    results.push_back(info);
                }
            }
        }));
    }
    for (auto& thread : threadPool) {
        thread.join();
    }
    std::sort(results.begin(), results.end(), [](const ServiceInfo& a, const ServiceInfo& b) {
        return a.port < b.port;
    });
}

std::string BannerGrabber::getTLSDetails(const std::string& ip, int port) {
    SSL_CTX* ctx = initializeSSLContext();
    if (!ctx) {
        return "Failed to initialize SSL context";
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        return "Failed to create socket";
    }
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr);
    if (connect(sock, (struct sockaddr*)&target, sizeof(target)) < 0) {
        close(sock);
        SSL_CTX_free(ctx);
        return "Failed to connect to server";
    }
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        close(sock);
        SSL_CTX_free(ctx);
        return "Failed to create SSL object";
    }
    SSL_set_fd(ssl, sock);
    int sslResult = SSL_connect(ssl);
    if (sslResult != 1) {
        int err = SSL_get_error(ssl, sslResult);
        std::string errorMsg = "SSL handshake failed: " + std::string(ERR_error_string(err, nullptr));
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return errorMsg;
    }
    std::stringstream ss;
    ss << "Protocol: " << SSL_get_version(ssl) << std::endl;
    ss << "Cipher: " << SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)) << std::endl;
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        X509_NAME* subjectName = X509_get_subject_name(cert);
        if (subjectName) {
            ss << "Subject: ";
            char commonName[256] = {0};
            int len = X509_NAME_get_text_by_NID(subjectName, NID_commonName, commonName, sizeof(commonName));
            if (len > 0) {
                if (len >= sizeof(commonName)) commonName[sizeof(commonName) - 1] = '\0';
                ss << "CN=" << commonName << ", ";
            }
            char orgName[256] = {0};
            len = X509_NAME_get_text_by_NID(subjectName, NID_organizationName, orgName, sizeof(orgName));
            if (len > 0) {
                if (len >= sizeof(orgName)) orgName[sizeof(orgName) - 1] = '\0';
                ss << "O=" << orgName << ", ";
            }
            char countryName[256] = {0};
            len = X509_NAME_get_text_by_NID(subjectName, NID_countryName, countryName, sizeof(countryName));
            if (len > 0) {
                if (len >= sizeof(countryName)) countryName[sizeof(countryName) - 1] = '\0';
                ss << "C=" << countryName;
            }
            ss << std::endl;
        }
        X509_NAME* issuerName = X509_get_issuer_name(cert);
        if (issuerName) {
            ss << "Issuer: ";
            char issuerCommonName[256] = {0};
            int len = X509_NAME_get_text_by_NID(issuerName, NID_commonName, issuerCommonName, sizeof(issuerCommonName));
            if (len > 0) {
                if (len >= sizeof(issuerCommonName)) issuerCommonName[sizeof(issuerCommonName) - 1] = '\0';
                ss << "CN=" << issuerCommonName << ", ";
            }
            char issuerOrgName[256] = {0};
            len = X509_NAME_get_text_by_NID(issuerName, NID_organizationName, issuerOrgName, sizeof(issuerOrgName));
            if (len > 0) {
                if (len >= sizeof(issuerOrgName)) issuerOrgName[sizeof(issuerOrgName) - 1] = '\0';
                ss << "O=" << issuerOrgName;
            }
            ss << std::endl;
        }
        ASN1_TIME* notBefore = X509_get_notBefore(cert);
        ASN1_TIME* notAfter = X509_get_notAfter(cert);
        if (notBefore && notAfter) {
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio) {
                ss << "Valid from: ";
                ASN1_TIME_print(bio, notBefore);
                char validityBuffer[256] = {0};
                BIO_read(bio, validityBuffer, sizeof(validityBuffer) - 1);
                ss << validityBuffer << std::endl;
                BIO_reset(bio);
                ss << "Valid until: ";
                ASN1_TIME_print(bio, notAfter);
                memset(validityBuffer, 0, sizeof(validityBuffer));
                BIO_read(bio, validityBuffer, sizeof(validityBuffer) - 1);
                ss << validityBuffer << std::endl;
                BIO_free(bio);
            }
        }
        STACK_OF(GENERAL_NAME)* san_names = static_cast<STACK_OF(GENERAL_NAME)*>(
            X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
        if (san_names) {
            ss << "Subject Alternative Names: ";
            int san_count = sk_GENERAL_NAME_num(san_names);
            for (int i = 0; i < san_count; i++) {
                GENERAL_NAME* current_name = sk_GENERAL_NAME_value(san_names, i);
                if (current_name->type == GEN_DNS) {
                    const char * dnsName = (const char*) ASN1_STRING_get0_data(current_name->d.dNSName);
                    int dnsNameLen = ASN1_STRING_length(current_name->d.dNSName);
                    ss << "DNS:" << std::string(dnsName, dnsNameLen);
                    if (i < san_count - 1) {
                        ss << ", ";
                    }
                }
            }
            sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
            ss << std::endl;
        }
        ss << "SHA-1 Fingerprint: ";
        unsigned char sha1_digest[SHA_DIGEST_LENGTH];
        X509_digest(cert, EVP_sha1(), sha1_digest, nullptr);
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sha1_digest[i]);
            if (i < SHA_DIGEST_LENGTH - 1) {
                ss << ":";
            }
        }
        ss << std::endl;
        X509_free(cert);
    } else {
        ss << "No certificate provided by server" << std::endl;
    }
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return ss.str();
}

std::map<std::string, std::string> BannerGrabber::parseHTTPHeaders(const std::string& httpResponse) {
    std::map<std::string, std::string> headers;
    std::istringstream responseStream(httpResponse);
    std::string line;
    bool firstLine = true;
    while (std::getline(responseStream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            break;
        }
        if (firstLine) {
            headers["Status"] = line;
            firstLine = false;
        } else {
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string name = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                size_t valueStart = value.find_first_not_of(" \t");
                if (valueStart != std::string::npos) {
                    value = value.substr(valueStart);
                }
                headers[name] = value;
            }
        }
    }
    return headers;
}

// New method implementations added below

std::string BannerGrabber::serializeDetails(const std::map<std::string, std::string>& details) {
    std::string result;
    for (const auto& pair : details) {
        if (!result.empty()) {
            result += ";";
        }
        result += pair.first + "=" + pair.second;
    }
    return result;
}

void BannerGrabber::writeCSVRow(std::ostream& os, const std::vector<std::string>& fields) {
    for (size_t i = 0; i < fields.size(); ++i) {
        if (i > 0) {
            os << ",";
        }
        std::string field = fields[i];
        // Quote the field if it contains commas, quotes, or newlines
        if (field.find(',') != std::string::npos ||
            field.find('"') != std::string::npos ||
            field.find('\n') != std::string::npos) {
            // Escape quotes by doubling them
            size_t pos = 0;
            while ((pos = field.find('"', pos)) != std::string::npos) {
                field.replace(pos, 1, "\"\"");
                pos += 2;
            }
            os << "\"" << field << "\"";
        } else {
            os << field;
        }
    }
    os << "\n";
}

void BannerGrabber::writeToCSV(const std::string& ip, const std::vector<ServiceInfo>& results, const std::string& filename) {
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        throw std::runtime_error("Unable to open file: " + filename);
    }

    // Write the CSV header
    outfile << "IP,Port,Protocol,Status,Service,Version,Banner,CertInfo,ServiceDetails\n";

    // Write each ServiceInfo as a row
    for (const auto& info : results) {
        std::vector<std::string> fields;
        fields.push_back(ip);                           // IP address
        fields.push_back(std::to_string(info.port));    // Port number
        fields.push_back(info.protocol);                // Protocol
        fields.push_back(info.status);                  // Status
        fields.push_back(info.service);                 // Service name
        fields.push_back(info.version);                 // Version
        fields.push_back(info.banner);                  // Banner
        fields.push_back(info.certInfo);                // Certificate info
        fields.push_back(serializeDetails(info.serviceDetails)); // Serialized service details
        writeCSVRow(outfile, fields);
    }

    outfile.close();
}