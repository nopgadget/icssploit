# ICSSploit - Industrial Control System Exploitation Framework

A Python-based exploitation framework for industrial control systems, similar to Metasploit but focused on ICS/SCADA protocols.

> **Disclaimer**: Usage of ICSSploit for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Quick Start

### Installation
```bash
git clone https://github.com/nopgadget/icssploit.git
cd icssploit
pip install -r requirements.txt
python main.py
```

### Basic Usage
```bash
# Start the framework
python main.py

# Show available modules
show all

# Use an exploit module
use exploits/plcs/siemens/s7_300_400_plc_control
set target 192.168.1.100
run

# Use a scanner
use scanners/s7comm_scan
set target 192.168.1.0/24
run

# Use a client for direct protocol interaction
use client/s7
set target 192.168.1.100
set port 102
run
```

## Features

### 🎯 Exploitation Modules
- **PLC Control**: Start/stop/reset industrial controllers
- **System Vulnerabilities**: Target CVE vulnerabilities in ICS systems

### 🔍 Discovery & Scanning
- **Network Scanners**: Discover ICS devices on networks
- **Protocol Scanners**: Identify supported protocols and services
- **Device Fingerprinting**: Gather detailed device information

### 🔐 Credential Testing
- **Brute Force**: Password attacks against ICS devices
- **Default Credentials**: Test common default passwords

### 🔌 Protocol Clients
- **8 Supported Protocols**: Direct interaction with industrial protocols
- **Module-like Interface**: Use clients exactly like exploitation modules
- **Real-time Communication**: Send/receive messages and control devices

## Supported Protocols

| Protocol | Client | Scanner | Exploits | Default Port |
|----------|--------|---------|----------|--------------|
| Modbus TCP | ✅ | ✅ | ✅ | 502 |
| S7comm | ✅ | ✅ | ✅ | 102 |
| S7comm Plus | ✅ | - | - | 102 |
| BACnet | ✅ | ✅ | - | 47808 |
| EtherNet/IP (CIP) | ✅ | ✅ | - | 44818 |
| OPC UA | ✅ | ✅ | - | 4840 |
| WDB (VxWorks) | ✅ | ✅ | ✅ | 17185 |
| Profinet DCP | - | ✅ | ✅ | - |
| 0MQ (ZeroMQ) | ✅ | ✅ | ✅ | 5555 |

## Module Categories

### Exploits
- **PLC Control**: Control logic controllers (start/stop/reset)
- **VxWorks**: Target VxWorks-based systems
- **QNX**: Exploit QNX real-time systems
- **Schneider**: Schneider Electric device exploits

### Scanners
- **Network Discovery**: Find ICS devices on networks
- **Protocol Detection**: Identify supported protocols
- **Device Enumeration**: Gather device information

### Credentials
- **Brute Force Attacks**: Password attacks against ICS authentication
- **Default Credentials**: Test common factory passwords

## Client System

The unified client system allows direct protocol interaction:

```bash
# List available clients
show client

# Use a client (like using a module)
use client/modbus
set target 192.168.1.100
set port 502
options
run

# Send protocol-specific commands
send read_coils 1 10
receive
call discover_devices

# Return to main menu
back
```

All clients support the same interface as modules: `set`, `options`, `run`, `check`, `back`.

## Documentation

### Client Documentation
- [Client Management System](docs/client_management.md) - Comprehensive client usage guide
- [Modbus TCP Client](docs/modbus_tcp_client.md) - Modbus protocol client
- [S7 Client](docs/s7_client.md) - Siemens S7 protocol client
- [WDB RPC Client](docs/wdbrpc_v2_client.md) - VxWorks debugging client

### Scanner Documentation
- [S7comm Scanner](docs/s7comm_scan.md) - Scan for Siemens PLCs
- [VxWorks Scanner](docs/vxworks_6_scan.md) - Scan for VxWorks devices
- [Profinet DCP Scanner](docs/profinet_dcp_scan.md) - Discover Profinet devices
- [Modbus Scanner](docs/modbus_scan.md) - Scan for Modbus devices
- [BACnet Scanner](docs/bacnet_scan.md) - Discover BACnet devices
- [OPC UA Scanner](docs/opcua_scan.md) - Find OPC UA servers
- [0MQ Scanner](docs/zmq_scan.md) - Discover ZeroMQ endpoints

### Credential Testing
- [S7 Brute Force](docs/s7_bruteforce.md) - Siemens PLC password attacks
- [SNMP Brute Force](docs/snmp_bruteforce.md) - SNMP community string attacks

### Exploit Documentation
- [Profinet Set IP](docs/profinet_set_ip.md) - Change device IP addresses

### Development
- [Creating Modules](docs/how_to_create_module.md) - Write custom modules
- [Loading Extra Modules](docs/load_extra_modules_from_folder.md) - Load external modules

## Dependencies

### Required
- Python 3.6+
- scapy
- paramiko
- pymodbus[serial]
- opcua
- pysnmp
- pyzmq

### Platform-Specific
- **Windows**: pyreadline3 (for tab completion)
- **All Platforms**: colorama (for terminal colors)

### Optional
- requests (for HTTP-based modules)
- python-nmap (for network scanning)

## Installation Options

### Full Installation (Recommended)
```bash
pip install -r requirements.txt
```

### Minimal Installation
```bash
pip install scapy paramiko pymodbus opcua pysnmp pyzmq colorama
# Add pyreadline3 on Windows
```

### libpcap Installation (for packet capture functionality)
If you need packet capture capabilities or encounter libpcap-related issues:
```bash
conda install conda-forge::libpcap
```

**Windows Users**: If you still see "No libpcap provider available" warnings after installing libpcap, try these additional steps:

1. **Install WinPcap alternative:**
```bash
conda install intake::winpcap
```

2. **Install Npcap (recommended):**
   - Download from: https://nmap.org/npcap/
   - Install with "Install Npcap in WinPcap API-compatible mode" checked

3. **Alternative Scapy backends:**
```bash
# Try installing these Scapy dependencies
pip install pypcap
pip install dnet
```

4. **Restart your terminal/conda environment** after installation

**Important**: This warning can usually be **safely ignored**. The ICSSploit framework uses Scapy for protocol communication, not raw packet capture, so the clients will work correctly even with this warning. The warning only affects advanced packet sniffing features.

## Project Information

- **Original Project**: Based on [routersploit](https://github.com/reverse-shell/routersploit)
- **Original Fork**: Revived version of [isf](https://github.com/dark-lbp/isf)
- **Fork Maintainer**: nopgadget
- **Version**: 0.2.0
- **License**: See LICENSE file

## Resources & References

### ICS Security Resources
- [ICS-CERT Advisories](https://us-cert.cisa.gov/ics/advisories)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Industrial Control Systems Cyber Emergency Response Team](https://us-cert.cisa.gov/ics)

### Protocol Documentation
- [Modbus Protocol Specification](http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [S7 Communication Protocol](https://wiki.wireshark.org/S7comm)
- [BACnet Protocol](http://www.bacnet.org/)
- [EtherNet/IP Specification](https://www.odva.org/technology-standards/key-technologies/ethernet-ip/)
- [OPC UA Specification](https://opcfoundation.org/about/opc-technologies/opc-ua/)

### Security Research
- [Industrial Control System Security Research](https://www.sans.org/white-papers/industrial-control-system-security/)
- [Critical Infrastructure Protection](https://www.dhs.gov/topic/critical-infrastructure-security)
- [SCADA Security Best Practices](https://www.us-cert.gov/sites/default/files/recommended_practices/NCCIC_ICS-CERT_Defense_in_Depth_2016_S508C.pdf)

### Vulnerability Databases
- [CVE Details - SCADA](https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttpr=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=100&sha=29e7987af0e1c96a2f9f86ce1b8e0ab9b7e0b0b1)
- [Shodan ICS Search](https://www.shodan.io/explore/category/industrial-control-systems)
- [Rapid7 Vulnerability Database](https://www.rapid7.com/db/)