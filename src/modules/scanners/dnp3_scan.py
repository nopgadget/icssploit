from src import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_table,
    validators,
)
from src.modules.clients.dnp3_client import DNP3Client
from src.utils import port_scan, export_table
from src.config import DEFAULT_PORTS

TABLE_HEADER = ['Device Type', 'Address', 'Status', 'Capabilities', 'Host', 'Port']
DNP3_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'DNP3 Device Scan',
        'authors': [
            'ICSSploit Team'  # icssploit module
        ],
        'description': 'Scan for DNP3 devices on the network and enumerate their properties.',
        'references': [
            'https://en.wikipedia.org/wiki/DNP3',
            'https://www.dnp.org/',
            'https://standards.ieee.org/standard/1815-2012.html',
        ],
        'devices': [
            'DNP3 (IEEE 1815) compliant devices',
            'SCADA systems',
            'RTUs (Remote Terminal Units)',
            'IEDs (Intelligent Electronic Devices)',
            'PLCs with DNP3 support',
        ],
    }

    target = exploits.Option('', "string for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    port = exploits.Option(DEFAULT_PORTS['dnp3'], 'DNP3 port, default is 20000/TCP', validators=validators.integer)
    local_address = exploits.Option(1, 'Local DNP3 address', validators=validators.integer)
    start_address = exploits.Option(1, 'Start DNP3 device address for discovery', validators=validators.integer)
    end_address = exploits.Option(50, 'End DNP3 device address for discovery', validators=validators.integer)
    enumerate = exploits.Option(False, 'Enumerate device points and properties', validators=validators.bool)
    get_device_info = exploits.Option(True, 'Get detailed device information', validators=validators.bool)
    timeout = exploits.Option(5, 'Connection timeout in seconds', validators=validators.integer)
    result = []

    def get_target_info(self, host, port):
        """Get DNP3 device information"""
        print_status(f"Scanning DNP3 device at {host}:{port}")
        
        try:
            # Try different common DNP3 addresses
            addresses_to_try = list(range(self.start_address, min(self.end_address + 1, 255)))
            
            for remote_addr in addresses_to_try:
                try:
                    target = DNP3Client(
                        name='DNP3Scanner', 
                        target=host, 
                        port=port,
                        local_address=self.local_address,
                        remote_address=remote_addr,
                        timeout=self.timeout
                    )
                    
                    # Try to connect and get device info
                    if target.connect():
                        print_success(f"Found DNP3 device at {host}:{port} with address {remote_addr}")
                        
                        device_type, address, status, capabilities, host_addr, port_str = target.get_target_info()
                        
                        self.result.append([device_type, address, status, capabilities, host_addr, port_str])
                        
                        # If device info is requested, get it
                        if self.get_device_info:
                            print_status(f"Getting device information for address {remote_addr}")
                            device_info = target.get_device_info()
                        
                        # If enumeration is requested, do it
                        if self.enumerate:
                            print_status(f"Enumerating points for device at address {remote_addr}")
                            points = target.enumerate_device()
                        
                        target.disconnect()
                        
                        # Only try one address per host for basic scanning
                        if not self.enumerate:
                            break
                            
                    else:
                        # Connection failed for this address, try next
                        continue
                        
                except Exception as addr_err:
                    # Error with this specific address, try next
                    print_error(f"Error testing address {remote_addr} on {host}:{port} - {addr_err}")
                    continue
            
            return len([r for r in self.result if r[4] == host]) > 0
                
        except Exception as err:
            print_error(f"Error scanning {host}:{port} - {err}")
            return False

    def discover_devices_on_host(self, host, port):
        """Discover DNP3 devices on a specific host by scanning addresses"""
        print_status(f"Discovering DNP3 devices on {host}:{port}")
        
        try:
            # Create a client for device discovery
            scanner = DNP3Client(
                name='DNP3Discoverer', 
                target=host, 
                port=port,
                local_address=self.local_address,
                timeout=self.timeout
            )
            
            # Discover devices using address range scanning
            address_range = range(self.start_address, min(self.end_address + 1, 255))
            devices = scanner.discover_devices(address_range)
            
            for device in devices:
                print_success(f"Discovered DNP3 device: Address {device.address} at {device.host}:{device.port}")
                
                # Get detailed info for each discovered device
                device_client = DNP3Client(
                    name=f'Device_{device.address}',
                    target=device.host,
                    port=device.port,
                    local_address=self.local_address,
                    remote_address=device.address,
                    timeout=self.timeout
                )
                
                if device_client.connect():
                    device_type, address, status, capabilities, host_addr, port_str = device_client.get_target_info()
                    
                    self.result.append([device_type, address, status, capabilities, host_addr, port_str])
                    
                    # Get additional info if requested
                    if self.get_device_info:
                        print_status(f"Getting device information for address {device.address}")
                        device_info = device_client.get_device_info()
                    
                    if self.enumerate:
                        print_status(f"Enumerating points for device at address {device.address}")
                        points = device_client.enumerate_device()
                    
                    device_client.disconnect()
            
            return len(devices) > 0
                
        except Exception as err:
            print_error(f"Error discovering devices on {host}:{port} - {err}")
            return False

    def test_dnp3_connectivity(self, host, port):
        """Test basic DNP3 connectivity without full enumeration"""
        print_status(f"Testing DNP3 connectivity to {host}:{port}")
        
        try:
            # Try a few common DNP3 addresses
            common_addresses = [1, 10, 100, 1000]
            
            for addr in common_addresses:
                if addr > self.end_address:
                    continue
                    
                try:
                    client = DNP3Client(
                        name='DNP3ConnTest',
                        target=host,
                        port=port,
                        local_address=self.local_address,
                        remote_address=addr,
                        timeout=self.timeout
                    )
                    
                    if client.test_connection():
                        print_success(f"DNP3 connectivity confirmed at {host}:{port} (address {addr})")
                        
                        device_type, address, status, capabilities, host_addr, port_str = client.get_target_info()
                        self.result.append([device_type, address, status, capabilities, host_addr, port_str])
                        
                        client.disconnect()
                        return True
                        
                except Exception as e:
                    continue
            
            return False
            
        except Exception as err:
            print_error(f"Error testing DNP3 connectivity to {host}:{port} - {err}")
            return False

    def run(self):
        self.result = []
        
        # Check if we have a specific target or need to scan
        if not self.target:
            print_error("No target specified. Please set target option.")
            return
        
        # First, try to discover hosts with open DNP3 ports
        try:
            nm = port_scan(protocol='TCP', target=self.target, port=self.port)
            
            discovered_hosts = []
            for host in nm.all_hosts():
                if nm[host]['tcp'][self.port]['state'] == "open":
                    print_success(f"Host: {host}, port:{self.port} is open")
                    discovered_hosts.append(host)
            
            if not discovered_hosts:
                print_error(f"No hosts with open port {self.port} found on network {self.target}")
                print_status("Trying direct DNP3 connectivity test...")
                
                # If no open ports found via nmap, try direct DNP3 test
                # Use the target directly if it's a single host
                import ipaddress
                try:
                    # Try to parse as single IP
                    ip = ipaddress.ip_address(self.target)
                    self.test_dnp3_connectivity(str(ip), self.port)
                except ipaddress.AddressValueError:
                    try:
                        # Try to parse as network
                        network = ipaddress.ip_network(self.target, strict=False)
                        # Test first few hosts in network
                        for i, ip in enumerate(network.hosts()):
                            if i >= 5:  # Limit to first 5 hosts
                                break
                            self.test_dnp3_connectivity(str(ip), self.port)
                    except Exception as e:
                        print_error(f"Error parsing target: {e}")
                        return
            else:
                # For each discovered host, try to get DNP3 device information
                for host in discovered_hosts:
                    if self.enumerate:
                        # Full enumeration - scan all addresses
                        self.discover_devices_on_host(host, self.port)
                    else:
                        # Quick scan - try common addresses
                        self.get_target_info(host, self.port)
        
        except Exception as e:
            print_error(f"Error during port scanning: {e}")
            # Fall back to direct testing
            try:
                import ipaddress
                ip = ipaddress.ip_address(self.target)
                self.test_dnp3_connectivity(str(ip), self.port)
            except:
                print_error("Could not parse target for direct testing")
                return
        
        # Remove duplicates and show results
        unique_devices = []
        seen = set()
        for device in self.result:
            device_key = (device[1], device[4], device[5])  # address, host, port
            if device_key not in seen:
                seen.add(device_key)
                unique_devices.append(device)
        
        if len(unique_devices) > 0:
            print_success(f"Found {len(unique_devices)} DNP3 devices")
            print_table(TABLE_HEADER, *unique_devices)
            print('\r')
            
            # Show summary of capabilities
            online_devices = [d for d in unique_devices if d[2] == "Online"]
            if online_devices:
                print_status(f"Summary: {len(online_devices)} devices online, {len(unique_devices) - len(online_devices)} offline")
                
                # Show address distribution
                addresses = [int(d[1]) for d in online_devices if d[1].isdigit()]
                if addresses:
                    print_status(f"DNP3 addresses found: {sorted(set(addresses))}")
        else:
            print_error(f"Didn't find any DNP3 devices on network {self.target}")
            print_status("Tips:")
            print_status("- Try different port numbers (common: 20000, 19999, 502)")
            print_status("- Increase address range (start_address/end_address)")
            print_status("- Check if devices use non-standard DNP3 configurations")

    def command_export(self, file_path, *args, **kwargs):
        """Export results to file"""
        unique_devices = []
        seen = set()
        for device in self.result:
            device_key = (device[1], device[4], device[5])  # address, host, port
            if device_key not in seen:
                seen.add(device_key)
                unique_devices.append(device)
        
        unique_devices = sorted(unique_devices, key=lambda x: (x[4], int(x[1]) if x[1].isdigit() else 0))
        export_table(file_path, TABLE_HEADER, unique_devices)
