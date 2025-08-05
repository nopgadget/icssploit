# Industrial Exploitation Framework
ICSSPLOIT(Industrial Exploitation Framework) is a exploitation framework based on Python, it's similar to metasploit framework. 

This project is a fork to revive icssploit and is authored by nopgadget.

ICSSPLOIT is based on open source project [routersploit](https://github.com/reverse-shell/routersploit).

## Disclaimer 
Usage of ICSSPLOIT for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program.


## ICS Protocol Clients
| Name               | Path                                   | Description            |
| -------------------| ---------------------------------------|:----------------------:|  
| modbus_tcp_client  | icssploit/clients/modbus_tcp_client.py | Modbus-TCP Client      |
| wdb2_client        | icssploit/clients/wdb2_client.py       | WdbRPC Version 2 Client(Vxworks 6.x)|
| s7_client          | icssploit/clients/s7_client.py         | s7comm Client(S7 300/400 PLC)       |


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
* gnureadline (OSX only)
* pyreadline3 (Windows only - for tab completion)
* requests
* paramiko
* beautifulsoup4
* pysnmp
* python-nmap
* scapy [We suggest install scapy manual with this official document](http://scapy.readthedocs.io/en/latest/installation.html)

## Install
    git clone https://github.com/nopgadget/icssploit/
    cd icssploit
    pip install -r requirements.txt
    python icssploit.py

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