# Industrial Exploitation Framework
ICSSPLOIT(Industrial Exploitation Framework) is a exploitation framework based on Python, it's similar to metasploit framework. 

This project is a fork to revive icssploit and is authored by nopgadget.

ICSSPLOIT is based on open source project [routersploit](https://github.com/reverse-shell/routersploit).

## 🆕 New Features

### Client Management System
- **Unified Client Interface**: Access all industrial protocol clients through a single command interface
- **8 Supported Protocols**: BACnet, Modbus, Modbus TCP, S7, S7 Plus, OPC UA, CIP, WDB2
- **Intelligent Tab Completion**: Context-aware completion for all client operations
- **Direct Method Calls**: Execute client methods directly from the command line
- **Integration with Modules**: Use clients alongside existing exploitation modules

### Improved Dependency Management
- **Conditional Imports**: Dependencies are imported only when needed for better startup performance
- **Flexible Installation**: Choose between full, basic, or minimal installation
- **Clear Error Messages**: Helpful error messages with installation instructions when dependencies are missing

## Disclaimer 
Usage of ICSSPLOIT for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program.


## ICS Protocol Clients
ICSSploit includes a comprehensive client management system for interacting with industrial protocols directly from the command line interface.

### Available Clients
| Name               | Path                                   | Description            |
| -------------------| ---------------------------------------|:----------------------:|  
| bacnet_client      | icssploit/clients/bacnet_client.py     | BACnet Client          |
| modbus_client      | icssploit/clients/modbus_client.py     | Modbus Client          |
| modbus_tcp_client  | icssploit/clients/modbus_tcp_client.py | Modbus-TCP Client      |
| s7_client          | icssploit/clients/s7_client.py         | S7comm Client(S7 300/400 PLC)       |
| s7plus_client      | icssploit/clients/s7plus_client.py     | S7comm Plus Client     |
| opcua_client       | icssploit/clients/opcua_client.py      | OPC UA Client          |
| cip_client         | icssploit/clients/cip_client.py        | CIP Client             |
| wdb2_client        | icssploit/clients/wdb2_client.py       | WdbRPC Version 2 Client(Vxworks 6.x)|

### Client Management Commands
```bash
# List available client types
client types

# Create a new client
client create <type> <name> [options]

# List all created clients
client list

# Connect to a client
client connect <name>

# Call client methods directly
client call <name> <method> [args...]

# Get help for a specific client type
client help <type>
```

### Example Usage
```bash
# Create and use a BACnet client (uses default port 47808)
client create bacnet my_bacnet ip=192.168.1.100
client connect my_bacnet
client call my_bacnet discover_devices

# Create and use a Modbus client (uses default port 502)
client create modbus my_modbus ip=192.168.1.101
client connect my_modbus
client call my_modbus read_holding_registers 0 10

# Create client with custom port
client create s7 my_s7 ip=192.168.1.102 port=103
client connect my_s7
client call my_s7 read_area "DB" 1 0 10
```


## Exploit Module
| Name                    | Path                                                              | Description                              |
| ------------------------| ------------------------------------------------------------------|:----------------------------------------:|  
| s7_300_400_plc_control  | exploits/plcs/siemens/s7_300_400_plc_control.py                   | S7-300/400 PLC start/stop                |
| s7_1200_plc_control     | exploits/plcs/siemens/s7_1200_plc_control.py                      | S7-1200 PLC start/stop/reset             |
| vxworks_rpc_dos         | exploits/plcs/vxworks/vxworks_rpc_dos.py                          | Vxworks RPC remote dos (CVE-2015-7599)  |
| quantum_140_plc_control | exploits/plcs/schneider/quantum_140_plc_control.py                | Schneider Quantum 140 series PLC start/stop |
| crash_qnx_inetd_tcp_service | exploits/plcs/qnx/crash_qnx_inetd_tcp_service.py              | QNX Inetd TCP service dos               |
| qconn_remote_exec       | exploits/plcs/qnx/qconn_remote_exec.py                            | QNX qconn remote code execution         |
| profinet_set_ip         | exploits/plcs/siemens/profinet_set_ip.py                          | Profinet DCP device IP config           |


## Scanner Module
| Name                    | Path                                                              | Description                             |
| ------------------------| ------------------------------------------------------------------|:---------------------------------------:|  
| profinet_dcp_scan       | scanners/profinet_dcp_scan.py                                     | Profinet DCP scanner                    |
| vxworks_6_scan          | scanners/vxworks_6_scan.py                                        | Vxworks 6.x scanner                     |
| s7comm_scan             | scanners/s7comm_scan.py                                           | S7comm scanner                          |
| enip_scan               | scanners/enip_scan.py                                             | EthernetIP scanner                      |



## ICS Protocols Module (Scapy Module)
These protocol can used in other Fuzzing framework like [Kitty](https://github.com/cisco-sas/kitty) or create your own client.
 
| Name                    | Path                                                              | Description                             |
| ------------------------| ------------------------------------------------------------------|:---------------------------------------:|  
| pn_dcp                  | icssploit/protocols/pn_dcp                                        | Profinet DCP Protocol                   |
| modbus_tcp              | icssploit/protocols/modbus_tcp                                    | Modbus TCP Protocol                     |
| wdbrpc2                 | icssploit/protocols/wdbrpc2                                       | WDB RPC Version 2 Protocol              |
| s7comm                  | icssploit/protocols/s7comm.py                                     | S7comm Protocol                         |



# Install

## Python requirements

### Core Dependencies (Required)
* paramiko
* beautifulsoup4
* pysnmp
* scapy [We suggest install scapy manual with this official document](http://scapy.readthedocs.io/en/latest/installation.html)
* telnetlib3
* pymodbus[serial]
* opcua
* pyreadline3 (Windows only - for tab completion)

### Core Dependencies
All dependencies are included in the main requirements.txt file. Some modules use conditional imports for better performance:
* requests - for HTTP requests and web-based modules (imported when needed)
* python-nmap - for port scanning functionality (imported when needed)

## Install

### Full Installation (Recommended)
```bash
git clone https://github.com/nopgadget/icssploit/
cd icssploit
pip install -r requirements.txt
python icssploit.py
```

### Basic Installation (Core functionality only)
```bash
git clone https://github.com/nopgadget/icssploit/
cd icssploit
pip install paramiko beautifulsoup4 pysnmp scapy telnetlib3 pymodbus opcua requests python-nmap
python icssploit.py
```

### Minimal Installation (For testing only)
```bash
git clone https://github.com/nopgadget/icssploit/
cd icssploit
# Install only the essential dependencies manually
pip install paramiko beautifulsoup4 pysnmp scapy telnetlib3 pymodbus opcua requests python-nmap
python icssploit.py
```

## Client Management System

ICSSploit includes a powerful client management system that allows you to interact with industrial protocols directly from the command line interface. This system provides:

- **Unified Interface**: All clients accessible through a single command interface
- **Easy Integration**: Use clients alongside existing modules
- **Intelligent Completion**: Tab completion for all client operations
- **Error Handling**: Comprehensive error handling with clear messages
- **Extensible**: Easy to add new client types

### Quick Start with Clients

1. **Start ICSSploit**:
   ```bash
   python icssploit.py
   ```

2. **Explore Available Clients**:
   ```bash
   client types
   ```

3. **Create and Use a Client**:
   ```bash
   # Create a BACnet client (uses default port 47808)
   client create bacnet my_bacnet ip=192.168.1.100
   
   # Or specify a custom port
   client create bacnet my_bacnet ip=192.168.1.100 port=47809
   
   # Connect to the device
   client connect my_bacnet
   
   # Discover devices
   client call my_bacnet discover_devices
   
   # Read properties
   client call my_bacnet read_property "device,1" "objectName"
   ```

4. **Get Help**:
   ```bash
   client help bacnet
   ```

### Default Ports

When creating clients, you can omit the port parameter to use the default port for each protocol:

- **BACnet**: 47808
- **Modbus**: 502  
- **S7**: 102
- **OPC UA**: 4840
- **CIP**: 44818
- **WDB2**: 17185

### Integration with Modules

Clients can be used in conjunction with ICSSploit modules:

1. **Information Gathering**: Use clients to discover devices and gather information
2. **Module Configuration**: Use gathered information to configure modules
3. **Exploitation**: Run modules against discovered targets
4. **Verification**: Use clients to verify successful exploitation

For detailed documentation, see [docs/client_management.md](docs/client_management.md).

## Configuration

ICSSPLOIT uses a Python-based configuration file located at `icssploit/config.py`. You can modify the settings in this file to customize the framework's behavior:

- **Logging settings**: Log file name, size limits, and log levels
- **Network settings**: Default timeouts and ports for various protocols
- **Interface settings**: Prompt customization and history file location
- **Security settings**: SSL verification and connection security options
- **Module settings**: Default categories and validation limits

For advanced customization, edit `icssploit/config.py` and restart the application.


# Usage
        root@kali:~/Desktop/temp/icssploit# python icssploit.py
        
          _____ _____  _____ _____ _____  _      ____ _____ _______
         |_   _/ ____|/ ____/ ____|  __ \| |    / __ \_   _|__   __|
           | || |    | (___| (___ | |__) | |   | |  | || |    | |   
           | || |     \___ \\___ \|  ___/| |   | |  | || |    | |   
          _| || |____ ____) |___) | |    | |___| |__| || |_   | |   
         |_____\_____|_____/_____/|_|    |______\____/_____|  |_|   
        
        
                        ICS Exploitation Framework

        Note     : ICSSPLOIT is a fork to revive icssploit at 
                   https://github.com/dark-lbp/icssploit

### Available Commands

**Global Commands:**
- `help` - Print help menu
- `use <module>` - Select a module for usage
- `exec <shell command>` - Execute a command in a shell
- `search <search term>` - Search for appropriate module
- `client <command>` - Client management commands
- `exit` - Exit icssploit

**Client Commands:**
- `client types` - List available client types
- `client create <type> <name> [options]` - Create a new client
- `client list` - List all created clients
- `client connect <name>` - Connect to a client
- `client call <name> <method> [args]` - Call client methods directly
- `client help <type>` - Get help for a specific client type
        Dev Team : nopgadget
        Version  : 0.2.0
        
        Exploits: 2 Scanners: 0 Creds: 13
        
        ICS Exploits:
            PLC: 2          ICS Switch: 0
            Software: 0
        
        icssploit >

## Exploits
    icssploit > use exploits/plcs/
    exploits/plcs/siemens/  exploits/plcs/vxworks/
    icssploit > use exploits/plcs/siemens/s7_300_400_plc_control
    exploits/plcs/siemens/s7_300_400_plc_control
    icssploit > use exploits/plcs/siemens/s7_300_400_plc_control
    icssploit (S7-300/400 PLC Control) >
    
## Tab Completion

ICSSPLOIT includes enhanced tab completion functionality:

### Use Command Tab Completion
```bash
icssploit > use [TAB]           # Shows: scanners/, exploits/, creds/
icssploit > use s[TAB]          # Shows: scanners/
icssploit > use s7[TAB]         # Shows: s7-related modules
icssploit > use scanners/[TAB]  # Shows: Available scanner modules
```

### Search Command Tab Completion
```bash
icssploit > search [TAB]        # Shows: Common search terms
icssploit > search p[TAB]       # Shows: p-related terms
icssploit > search plc[TAB]     # Shows: plc-related terms
```

**Note**: Tab completion requires readline support. On Windows, `pyreadline3` is automatically installed via requirements.txt. On other platforms, readline should work by default.


## Options
### Display module options:
    icssploit (S7-300/400 PLC Control) > show options
    
    Target options:
    
       Name       Current settings     Description
       ----       ----------------     -----------
       target                          Target address e.g. 192.168.1.1
       port       102                  Target Port
    
    
    Module options:
    
       Name        Current settings     Description
       ----        ----------------     -----------
       slot        2                    CPU slot number.
       command     1                    Command 0:start plc, 1:stop plc.
    
    
    icssploit (S7-300/400 PLC Control) >
    
### Set options
    icssploit (S7-300/400 PLC Control) > set target 192.168.70.210
    [+] {'target': '192.168.70.210'}
    

## Run module
    icssploit (S7-300/400 PLC Control) > run
    [*] Running module...
    [+] Target is alive
    [*] Sending packet to target
    [*] Stop plc
    icssploit (S7-300/400 PLC Control) >
    
## Display information about exploit
    icssploit (S7-300/400 PLC Control) > show info
    
    Name:
    S7-300/400 PLC Control
    
    Description:
    Use S7comm command to start/stop plc.
    
    Devices:
    -  Siemens S7-300 and S7-400 programmable logic controllers (PLCs)
    
    Authors:
    -  wenzhe zhu <jtrkid[at]gmail.com>
    
    References:
    
    icssploit (S7-300/400 PLC Control) >
    
# Documents
* [Modbus-TCP Client usage](docs/modbus_tcp_client.md)
* [WDBRPCV2 Client usage](docs/wdbrpc_v2_client.md)
* [S7comm Client usage](docs/s7_client.md)
* [SNMP_bruteforce usage](docs/snmp_bruteforce.md)
* [S7 300/400 PLC password bruteforce usage](docs/s7_bruteforce.md)
* [Vxworks 6.x Scanner usage](docs/vxworks_6_scan.md)
* [Profient DCP Scanner usage](docs/profinet_dcp_scan.md)
* [S7comm PLC Scanner usage](docs/s7comm_scan.md)
* [Profinet DCP Set ip module usage](docs/profinet_set_ip.md)
* [Load modules from extra folder](docs/load_extra_modules_from_folder.md)
* [How to write your own module](docs/how_to_create_module.md)