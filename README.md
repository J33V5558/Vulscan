# Network Scanner

## Overview
The *Network Scanner* is a tool developed in *C++* that scans a given network to scan its ports, services. It helps users assess security risks by detecting open ports, outdated services, and misconfigurations. The scanner leverages well-known scanning techniques to provide accurate and detailed reports.

## Features
- *Port Scanning*: Identifies open ports and running services.
- *Vulnerability Detection*: Correlates findings with known vulnerabilities (CVE/NVD databases can be integrated).
- *Custom Scanning*: Allows users to specify target IPs, port ranges, and scan modes.
- *Detailed Reporting*: Generates comprehensive scan reports in csv formats.
- *User-Friendly Interface*: CLI-based with easy-to-use options.
- *OS Detection(In progress)*:

## Installation
### Prerequisites
Ensure you have the following installed on your system:
- *C++ Compiler* (GCC/Clang/MSVC)
- *Boost Library* (if used for networking)
- *Nmap* (optional for external integration)

### Build Instructions
sh
git clone https://github.com/yourusername/network-vulnerability-scanner.git
cd network-vulnerability-scanner
g++ -std=c++17 -o <csv-file-name> <main.cpp file-name> <xbanner_grabber.cpp file-name> <packet_capture.cpp file-name> <os_fingerprint.cpp file-name> -lssl -lcrypto -lpthread -lpcap 


## Usage
Run the scanner with the required options:
sh
 sudo ./<csv-file-name> --ip-range <192.168.1> <ip-range> --quick-scan

### Command-Line Options
- -t <target_ip> : Target IP address
- -p <port_range> : Range of ports to scan
- --report <filename> : Save results to a file

## Contribution
We welcome contributions! Follow these steps:
1. Fork the repository.
2. Create a feature branch (git checkout -b feature-name).
3. Commit your changes (git commit -m "Add new feature").
4. Push to the branch (git push origin feature-name).
5. Open a pull request.
