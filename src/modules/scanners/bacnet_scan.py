from src import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_table,
    validators,
)
from src.modules.clients.bacnet_client import BACnetClient
from src.utils import port_scan, export_table
from src.config import DEFAULT_PORTS

TABLE_HEADER = ['Device Name', 'Vendor Name', 'Model Name', 'Firmware Version', 'System Status', 'Max APDU Length', 'IP Address']
BACNET_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'BACnet Device Scan',
        'authors': [
            'ICSSploit Team'  # icssploit module
        ],
        'description': 'Scan for BACnet devices on the network and enumerate their properties.',
        'references': [
            'https://www.bacnet.org/',
        ],
        'devices': [
            'BACnet compliant devices',
        ],
    }

    target = exploits.Option('', "string for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    port = exploits.Option(47808, 'BACnet port, default is 47808/UDP', validators=validators.integer)
    timeout = exploits.Option(10, 'Discovery timeout in seconds', validators=validators.integer)
    enumerate = exploits.Option(False, 'Enumerate device objects and properties', validators=validators.bool)
    check_permissions = exploits.Option(False, 'Check read/write permissions', validators=validators.bool)
    result = []

    def get_target_info(self, host, port):
        """Get BACnet device information"""
        print_status(f"Scanning BACnet device at {host}:{port}")
        
        try:
            target = BACnetClient(name='BACnetScanner', ip=host, port=port, timeout=3)
            
            # Try to connect and get device info
            if target.connect():
                device_name, vendor_name, model_name, firmware_version, system_status, max_apdu_length = target.get_target_info()
                ip_address = host
                
                # Only add if we got some meaningful information
                if device_name != 'Unknown' or vendor_name != 'Unknown':
                    self.result.append([device_name, vendor_name, model_name, firmware_version,
                                     system_status, max_apdu_length, ip_address])
                    
                    # If enumeration is requested, do it
                    if self.enumerate:
                        print_status(f"Enumerating objects for device at {host}")
                        objects = target.enumerate_device()
                        for obj_type, instances in objects.items():
                            print_status(f"  {obj_type}: {len(instances)} objects found")
                            for instance, name in instances[:5]:  # Show first 5
                                print_status(f"    {obj_type},{instance}: {name}")
                    
                    # If permission check is requested, do it
                    if self.check_permissions:
                        print_status(f"Checking permissions for device at {host}")
                        permissions = target.check_permissions()
                        for perm_name, has_perm in permissions.items():
                            status = "OK" if has_perm else "FAIL"
                            print_status(f"    {status} {perm_name}")
                
                target.disconnect()
                return True
            else:
                print_error(f"Could not connect to BACnet device at {host}:{port}")
                return False
                
        except Exception as err:
            print_error(f"Error scanning {host}:{port} - {err}")
            return False

    def discover_devices(self, host, port):
        """Discover BACnet devices using Who-Is requests"""
        print_status(f"Discovering BACnet devices from {host}:{port}")
        
        try:
            target = BACnetClient(name='BACnetDiscoverer', ip=host, port=port, timeout=3)
            
            if target.connect():
                # Discover devices
                devices = target.discover_devices(timeout=self.timeout)
                
                for device in devices:
                    print_success(f"Discovered BACnet device: {device.device_id} at {device.address}")
                    
                    # Try to get info for each discovered device
                    device_client = BACnetClient(name=f'Device_{device.device_id}', 
                                               ip=device.address, port=port, timeout=3)
                    if device_client.connect():
                        device_name, vendor_name, model_name, firmware_version, system_status, max_apdu_length = device_client.get_target_info()
                        
                        self.result.append([device_name, vendor_name, model_name, firmware_version,
                                         system_status, max_apdu_length, device.address])
                        
                        device_client.disconnect()
                
                target.disconnect()
                return True
            else:
                print_error(f"Could not connect for discovery from {host}:{port}")
                return False
                
        except Exception as err:
            print_error(f"Error discovering devices from {host}:{port} - {err}")
            return False

    def run(self):
        self.result = []
        
        # First, try to discover devices using port scan
        nm = port_scan(protocol='UDP', target=self.target, port=self.port)
        
        discovered_hosts = []
        for host in nm.all_hosts():
            if nm[host]['udp'][self.port]['state'] == "open":
                print_success(f"Host: {host}, port:{self.port} is open")
                discovered_hosts.append(host)
        
        if not discovered_hosts:
            print_error(f"No BACnet devices found on network {self.target}")
            print_status("Trying direct discovery...")
            
            # If no devices found via port scan, try direct discovery
            # Use the first host in the target range for discovery
            import ipaddress
            try:
                network = ipaddress.ip_network(self.target, strict=False)
                first_host = str(network.network_address + 1)
                self.discover_devices(first_host, self.port)
            except Exception as e:
                print_error(f"Error in direct discovery: {e}")
                return
        else:
            # For each discovered host, try to get device information
            for host in discovered_hosts:
                self.get_target_info(host=host, port=self.port)
        
        # Remove duplicates and show results
        unique_devices = [list(x) for x in set(tuple(x) for x in self.result)]
        
        if len(self.result) > 0:
            print_success(f"Found {len(self.result)} BACnet devices")
            print_table(TABLE_HEADER, *unique_devices)
            print('\r')
        else:
            print_error(f"Didn't find any BACnet devices on network {self.target}")

    def command_export(self, file_path, *args, **kwargs):
        unique_devices = [list(x) for x in set(tuple(x) for x in self.result)]
        unique_devices = sorted(unique_devices)
        export_table(file_path, TABLE_HEADER, unique_devices) 