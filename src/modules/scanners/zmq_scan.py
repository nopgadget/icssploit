from src import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_table,
    validators,
)
from src.modules.clients.zmq_client import ZMQClient, ZMQSocketType, ZMQTransport
from src.utils import port_scan, export_table
from src.config import DEFAULT_PORTS

TABLE_HEADER = ['Socket Type', 'Transport', 'Status', 'Accessible', 'Address', 'Port']
ZMQ_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': '0MQ Device Scan',
        'authors': [
            'ICSSploit Team'  # icssploit module
        ],
        'description': 'Scan for 0MQ devices on the network and enumerate their properties.',
        'references': [
            'https://pyzmq.readthedocs.io/en/latest/',
            'https://zeromq.org/',
        ],
        'devices': [
            '0MQ compliant devices',
        ],
    }

    target = exploits.Option('', "string for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    port = exploits.Option(5555, '0MQ port, default is 5555/TCP', validators=validators.integer)
    start_port = exploits.Option(5555, 'Start port for device discovery', validators=validators.integer)
    end_port = exploits.Option(5565, 'End port for device discovery', validators=validators.integer)
    socket_types = exploits.Option('REQ,SUB', 'Comma-separated list of socket types to test', 
                                  validators=validators.choice(['REQ', 'SUB', 'PUB', 'PUSH', 'PULL', 'PAIR', 'DEALER', 'ROUTER']))
    transport = exploits.Option('TCP', 'Transport protocol: TCP, IPC, INPROC', 
                               validators=validators.choice(['TCP', 'IPC', 'INPROC']))
    enumerate = exploits.Option(False, 'Enumerate device capabilities and properties', validators=validators.bool)
    check_permissions = exploits.Option(False, 'Check send/receive permissions', validators=validators.bool)
    result = []

    def get_target_info(self, host, port):
        """Get 0MQ device information"""
        print_status(f"Scanning 0MQ device at {host}:{port}")
        
        try:
            # Parse socket types to test
            socket_type_list = [s.strip() for s in self.socket_types.split(',')]
            
            for socket_type_name in socket_type_list:
                try:
                    socket_type = ZMQSocketType[socket_type_name]
                    transport = ZMQTransport[self.transport]
                    
                    target = ZMQClient(name='ZMQScanner', address=host, port=port, 
                                     socket_type=socket_type, transport=transport, timeout=3)
                    
                    # Try to connect and get device info
                    if target.connect():
                        device_type, unit_id, status, accessible, address, port = target.get_target_info()
                        
                        # Only add if we got some meaningful information
                        if status != 'offline' or accessible != 'False':
                            self.result.append([device_type, unit_id, status, accessible,
                                             address, port])
                            
                            # If enumeration is requested, do it
                            if self.enumerate:
                                print_status(f"Enumerating capabilities for device at {host}")
                                capabilities = target.enumerate_device()
                                for cap_type, instances in capabilities.items():
                                    print_status(f"  {cap_type}: {len(instances)} capabilities found")
                                    for item, value in instances[:5]:  # Show first 5
                                        print_status(f"    {cap_type}[{item}]: {value}")
                            
                            # If permission check is requested, do it
                            if self.check_permissions:
                                print_status(f"Checking permissions for device at {host}")
                                permissions = target.check_permissions()
                                for perm_name, has_perm in permissions.items():
                                    status = "✓" if has_perm else "✗"
                                    print_status(f"    {status} {perm_name}")
                            
                            target.disconnect()
                            break  # Found device with this socket type, try next port
                            
                        else:
                            target.disconnect()
                            
                except KeyError:
                    print_error(f"Unknown socket type: {socket_type_name}")
                    continue
                except Exception as e:
                    print_error(f"Error testing socket type {socket_type_name}: {e}")
                    continue
            else:
                print_error(f"Could not connect for discovery from {host}:{port}")
                return False
                
        except Exception as err:
            print_error(f"Error discovering devices from {host}:{port} - {err}")
            return False

    def discover_devices(self, host, port):
        """Discover 0MQ devices on a specific host and port"""
        print_status(f"Discovering 0MQ devices on {host}:{port}")
        
        try:
            # Parse socket types to test
            socket_type_list = [s.strip() for s in self.socket_types.split(',')]
            transport = ZMQTransport[self.transport]
            
            for socket_type_name in socket_type_list:
                try:
                    socket_type = ZMQSocketType[socket_type_name]
                    
                    target = ZMQClient(name='ZMQScanner', address=host, port=port, 
                                     socket_type=socket_type, transport=transport, timeout=2)
                    
                    # Try to discover devices
                    devices = target.discover_devices(self.start_port, self.end_port)
                    
                    for device in devices:
                        device_type = f"{device.socket_type.name}"
                        unit_id = f"{device.transport.value}"
                        status = "online" if device.connected else "offline"
                        accessible = "True" if device.connected else "False"
                        address = device.address
                        port = device.port
                        
                        self.result.append([device_type, unit_id, status, accessible, address, port])
                        print_success(f"Found 0MQ device: {device_type} at {address}:{port}")
                    
                    target.disconnect()
                    
                except KeyError:
                    print_error(f"Unknown socket type: {socket_type_name}")
                    continue
                except Exception as e:
                    print_error(f"Error testing socket type {socket_type_name}: {e}")
                    continue
                    
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
            print_error(f"No 0MQ devices found on network {self.target}")
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
        
        if unique_devices:
            print_success(f"Found {len(unique_devices)} 0MQ devices")
            print_table(TABLE_HEADER, *unique_devices)
            
            # Store results for export
            global ZMQ_DEVICES
            ZMQ_DEVICES = unique_devices
        else:
            print_error("No 0MQ devices found")


def export_results(filename):
    """Export scan results to CSV file"""
    if not ZMQ_DEVICES:
        print_error("No scan results to export")
        return
    
    try:
        export_table(filename, TABLE_HEADER, ZMQ_DEVICES)
        print_success(f"Results exported to {filename}")
    except Exception as e:
        print_error(f"Failed to export results: {e}") 