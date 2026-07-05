# pmap
A minimal port scanner inspired by **nmap**, written in Python.

## Features
- TCP Connect scan
- TCP SYN (half-open) scan
- UDP scan
- TCP ACK scan
- Banner grabbing (`-A`)
- Scan:
  - Top 100 ports (`-F`)
  - Top 1000 ports (default)
  - Custom ports
  - Port ranges
  - All 65535 ports

## Requirements
- Python 3
- Scapy

## Installation
Clone the repository:
```bash
git clone https://github.com/losthread/pscan.git
cd pscan
```

Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate      # Linux/macOS
# venv\Scripts\activate       # Windows
```

Install the dependencies:
```bash
pip install -r requirements.txt
pip install -e .
```

> **Note:** SYN and ACK scans require root/administrator privileges because they use raw packets.

## Usage
Scan the top 1000 ports:

```bash
pscan <target>
```

Scan specific ports:
```bash
pscan <target> -p 22,80,443
```

Scan a port range:
```bash
pscan <target> -p 1-1024
```

Scan all ports:
```bash
pscan <target> -a
```

Verbose output: (shows all ports regardless of being open or closed or filtered)
```bash
pscan <target> -v
```

Fast mode (top 100 ports):
```bash
pscan <target> -F
```

TCP SYN scan: (target device's firewall is less likely to log your IP)
```bash
sudo pscan <target> -sS
```

UDP scan: (sends UDP packets)
```bash
pscan <target> -sU
```

TCP ACK scan: (detects firewall by sending tcp ack)
```bash
sudo pscan <target> -sA
```

Banner grabbing: (tells about the service running on that port if any)
```bash
pscan <target> -A
```

## Scan Types

### TCP Connect
Performs a full TCP three-way handshake using Python sockets.

### TCP SYN
Performs a half-open scan by sending a SYN packet and analyzing the response without establishing a full TCP connection.

### UDP
Sends an empty UDP datagram. A UDP reply indicates an open port, while no response is reported as `OPEN|FILTERED`.

### TCP ACK
Sends an ACK packet to determine whether a firewall is filtering the port. Reports `UNFILTERED` or `FILTERED`.

# Disclaimer
Disclaimer: Use this tool only on systems you own or are explicitly authorized to test. The author is not responsible for any misuse or damage caused by this software.