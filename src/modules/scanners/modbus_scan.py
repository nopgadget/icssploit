from src import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_table,
    validators,
)
from src.modules.clients.modbus_client import ModbusClient
from src.utils import port_scan, export_table
from src.config import DEFAULT_PORTS

TABLE_HEADER = ['Device Type', 'Unit ID', 'Status', 'Registers Accessible', 'Address', 'Port']
MODBUS_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'Modbus Device Scan',
        'authors': [
            'ICSSploit Team'  # icssploit module
        ],
        'description': 'Scan for Modbus devices on the network and enumerate their properties.',
        'references': [
            'https://modbus.org/',
        ],
        'devices': [
            'Modbus TCP/RTU compliant devices',
        ],
    }

    target = exploits.Option('', "string for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    port = exploits.Option(DEFAULT_PORTS['modbus'], 'Modbus port, default is 502/TCP', validators=validators.integer)
    device_type = exploits.Option('TCP', 'Device type: TCP or RTU', validators=validators.choice(['TCP', 'RTU']))
    start_unit_id = exploits.Option(1, 'Start unit ID for device discovery', validators=validators.integer)
    end_unit_id = exploits.Option(10, 'End unit ID for device discovery', validators=validators.integer)
    enumerate = exploits.Option(False, 'Enumerate device registers and properties', validators=validators.bool)
    check_permissions = exploits.Option(False, 'Check read/write permissions', validators=validators.bool)
    result = []

    def get_target_info(self, host, port):
        """Get Modbus device information"""
        print_status(f"Scanning Modbus device at {host}:{port}")
        
        try:
            target = ModbusClient(name='ModbusScanner', ip=host, port=port, 
                                device_type=self.device_type, timeout=3)
            
            # Try to connect and get device info
            if target.connect():
                device_type, unit_id, status, registers_accessible, address, port = target.get_target_info()
                ip_address = host
                
                # Only add if we got some meaningful information
                if status != 'Unknown' or registers_accessible != 'False':
                    self.result.append([device_type, unit_id, status, registers_accessible,
                                     address, port])
                    
                    # If enumeration is requested, do it
                    if self.enumerate:
                        print_status(f"Enumerating registers for device at {host}")
                        registers = target.enumerate_device()
                        for reg_type, instances in registers.items():
                            print_status(f"  {reg_type}: {len(instances)} registers found")
                            for addr, value in instances[:5]:  # Show first 5
                                print_status(f"    {reg_type}[{addr}]: {value}")
                    
                    # If permission check is requested, do it
                    if self.check_permissions:
                        print_status(f"Checking permissions for device at {host}")
                        permissions = target.check_permissions()
                        for perm_name, has_perm in permissions.items():
                            status = "✓" if has_perm else "✗"
                            print_status(f"    {status} {perm_name}")
                
                target.disconnect()
                return True
            else:
                print_error(f"Could not connect to Modbus device at {host}:{port}")
                return False
                
        except Exception as err:
            print_error(f"Error scanning {host}:{port} - {err}")
            return False

    def discover_devices(self, host, port):
        """Discover Modbus devices using unit ID scanning"""
        print_status(f"Discovering Modbus devices from {host}:{port}")
        
        try:
            target = ModbusClient(name='ModbusDiscoverer', ip=host, port=port, 
                                device_type=self.device_type, timeout=3)
            
            if target.connect():
                # Discover devices by scanning unit IDs
                devices = target.discover_devices(start_unit_id=self.start_unit_id, 
                                               end_unit_id=self.end_unit_id)
                
                for device in devices:
                    print_success(f"Discovered Modbus device: Unit ID {device.unit_id} at {device.address}")
                    
                    # Try to get info for each discovered device
                    device_client = ModbusClient(name=f'Device_{device.unit_id}', 
                                               ip=device.address, port=device.port,
                                               unit_id=device.unit_id, device_type=device.device_type)
                    if device_client.connect():
                        device_type, unit_id, status, registers_accessible, address, port = device_client.get_target_info()
                        
                        self.result.append([device_type, unit_id, status, registers_accessible,
                                         address, port])
                        
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
        nm = port_scan(protocol='TCP', target=self.target, port=self.port)
        
        discovered_hosts = []
        for host in nm.all_hosts():
            if nm[host]['tcp'][self.port]['state'] == "open":
                print_success(f"Host: {host}, port:{self.port} is open")
                discovered_hosts.append(host)
        
        if not discovered_hosts:
            print_error(f"No Modbus devices found on network {self.target}")
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
            print_success(f"Found {len(self.result)} Modbus devices")
            print_table(TABLE_HEADER, *unique_devices)
            print('\r')
        else:
            print_error(f"Didn't find any Modbus devices on network {self.target}")

    def command_export(self, file_path, *args, **kwargs):
        unique_devices = [list(x) for x in set(tuple(x) for x in self.result)]
        unique_devices = sorted(unique_devices)
        export_table(file_path, TABLE_HEADER, unique_devices) 