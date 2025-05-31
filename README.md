# Advanced CLI Port Scanner in Python

## Overview

This is a feature-rich command-line port scanner written in Python. It enables users to scan IP addresses or domain names for open ports, gather service banners, perform OS fingerprinting, and export results to JSON or CSV formats.

## Features

* ✅ Scan single targets (IP or domain)
* ✅ Subnet scanning via CIDR (e.g., `192.168.1.0/24`)
* ✅ Load targets from a file (supports domains/IPs)
* ✅ TCP and UDP scanning support
* ✅ Banner grabbing from open ports
* ✅ OS fingerprinting using Nmap
* ✅ Multithreaded scanning for speed (default 100 threads)
* ✅ Export results to CSV and JSON
* ✅ Color-coded terminal output for better readability

## Dependencies

Install the following Python packages:

```bash
pip install colorama python-nmap
```

Ensure `nmap` is installed on your system and available in the system PATH:

```bash
sudo apt install nmap         # Linux
brew install nmap             # macOS
choco install nmap            # Windows (via Chocolatey)
```

## Usage

Run the scanner with Python:

```bash
python enhanced_port_scanner.py
```

### User Prompts

1. **Scan Type**: Single target / Subnet / File input
2. **Target**: IP address or domain name, CIDR subnet, or filename
3. **Port Range**: Starting and ending port
4. **Scan Protocol**: TCP or UDP
5. **Threads**: Number of concurrent scan threads
6. **OS Detection**: Enable or skip OS fingerprinting
7. **Save Results**: Save to `.json` or `.csv`

## Example Outputs

**Terminal**:

```
[12:30:01] Scanning google.com (142.250.72.206)
[12:30:02] 142.250.72.206:80 OPEN - HTTP/1.1 Google Server
[12:30:02] [OS] 142.250.72.206 - Linux 4.X
```

**JSON Export**:

```json
[
  {
    "ip": "142.250.72.206",
    "port": 80,
    "protocol": "TCP",
    "banner": "HTTP/1.1 Google Server",
    "os": "Linux 4.X"
  }
]
```

## Building Executable

You can convert the script into a standalone executable using PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile enhanced_port_scanner.py
```

The executable will be located in the `dist/` directory.

## Legal Notice

Use this tool responsibly. Only scan systems you have explicit permission to audit. Unauthorized scanning may be illegal.

## Author

Developed by \[Your Name] - Inspired by real-world network security tools.

---

Feel free to contribute or suggest improvements!
