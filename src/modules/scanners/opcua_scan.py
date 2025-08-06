from src import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_table,
    validators,
)
from src.modules.clients.opcua_client import OPCUAClient
from src.utils import port_scan, export_table
from src.config import DEFAULT_PORTS

TABLE_HEADER = ['Server Name', 'Server URI', 'Application URI', 'Product URI', 'Software Version', 'Build Number']
OPCUA_SERVERS = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'OPC UA Server Scan',
        'authors': [
            'ICSSploit Team'  # icssploit module
        ],
        'description': 'Scan for OPC UA servers on the network and enumerate their properties.',
        'references': [
            'https://opcfoundation.org/',
        ],
        'devices': [
            'OPC UA compliant servers',
        ],
    }

    target = exploits.Option('', "string for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    port = exploits.Option(DEFAULT_PORTS['opcua'], 'OPC UA port, default is 4840/TCP', validators=validators.integer)
    security_policy = exploits.Option('None', 'Security policy', validators=validators.choice(['None', 'Basic128Rsa15', 'Basic256', 'Basic256Sha256']))
    security_mode = exploits.Option('None', 'Security mode', validators=validators.choice(['None', 'Sign', 'SignAndEncrypt']))
    username = exploits.Option('', 'Username for authentication')
    password = exploits.Option('', 'Password for authentication')
    enumerate = exploits.Option(False, 'Enumerate server nodes and properties', validators=validators.bool)
    check_permissions = exploits.Option(False, 'Check read/write permissions', validators=validators.bool)
    get_endpoints = exploits.Option(False, 'Get server endpoints', validators=validators.bool)
    result = []

    def get_target_info(self, host, port):
        """Get OPC UA server information"""
        print_status(f"Scanning OPC UA server at {host}:{port}")
        
        try:
            # Construct OPC UA URL
            url = f"opc.tcp://{host}:{port}"
            
            target = OPCUAClient(name='OPCUAScanner', url=url, 
                                security_policy=self.security_policy, 
                                security_mode=self.security_mode,
                                username=self.username if self.username else None,
                                password=self.password if self.password else None,
                                timeout=5)
            
            # Try to connect and get server info
            if target.test_connection():
                server_name, server_uri, application_uri, product_uri, software_version, build_number = target.get_target_info()
                
                # Only add if we got some meaningful information
                if server_name != 'Unknown' or server_uri != 'Unknown':
                    self.result.append([server_name, server_uri, application_uri,
                                     product_uri, software_version, build_number])
                    
                    # If enumeration is requested, do it
                    if self.enumerate:
                        print_status(f"Enumerating nodes for server at {host}")
                        nodes_by_path = target.enumerate_device()
                        for path_name, nodes in nodes_by_path.items():
                            print_status(f"  {path_name}: {len(nodes)} nodes found")
                            for node in nodes[:5]:  # Show first 5
                                print_status(f"    {path_name}/{node.browse_name}: {node.node_class}")
                    
                    # If permission check is requested, do it
                    if self.check_permissions:
                        print_status(f"Checking permissions for server at {host}")
                        permissions = target.check_permissions()
                        for perm_name, has_perm in permissions.items():
                            status = "✓" if has_perm else "✗"
                            print_status(f"    {status} {perm_name}")
                    
                    # If endpoint enumeration is requested, do it
                    if self.get_endpoints:
                        print_status(f"Getting endpoints for server at {host}")
                        endpoints = target.get_endpoints()
                        for i, endpoint in enumerate(endpoints):
                            print_status(f"    Endpoint {i+1}: {endpoint['endpoint_url']}")
                            print_status(f"      Security Policy: {endpoint['security_policy_uri']}")
                            print_status(f"      Security Mode: {endpoint['security_mode']}")
                
                return True
            else:
                print_error(f"Could not connect to OPC UA server at {host}:{port}")
                return False
                
        except Exception as err:
            print_error(f"Error scanning {host}:{port} - {err}")
            return False

    def discover_servers(self, host, port):
        """Discover OPC UA servers using server discovery"""
        print_status(f"Discovering OPC UA servers from {host}:{port}")
        
        try:
            # Construct OPC UA URL
            url = f"opc.tcp://{host}:{port}"
            
            target = OPCUAClient(name='OPCUADiscoverer', url=url, 
                                security_policy=self.security_policy, 
                                security_mode=self.security_mode,
                                username=self.username if self.username else None,
                                password=self.password if self.password else None,
                                timeout=5)
            
            if target.test_connection():
                # Discover servers
                servers = target.discover_servers()
                
                for server in servers:
                    print_success(f"Discovered OPC UA server: {server.name} at {server.url}")
                    
                    # Add server info to results
                    self.result.append([server.name, server.server_uri, server.application_uri,
                                     server.product_uri, 'Unknown', 'Unknown'])
                
                return True
            else:
                print_error(f"Could not connect for discovery from {host}:{port}")
                return False
                
        except Exception as err:
            print_error(f"Error discovering servers from {host}:{port} - {err}")
            return False

    def run(self):
        self.result = []
        
        # First, try to discover servers using port scan
        nm = port_scan(protocol='TCP', target=self.target, port=self.port)
        
        discovered_hosts = []
        for host in nm.all_hosts():
            if nm[host]['tcp'][self.port]['state'] == "open":
                print_success(f"Host: {host}, port:{self.port} is open")
                discovered_hosts.append(host)
        
        if not discovered_hosts:
            print_error(f"No OPC UA servers found on network {self.target}")
            print_status("Trying direct discovery...")
            
            # If no servers found via port scan, try direct discovery
            # Use the first host in the target range for discovery
            import ipaddress
            try:
                network = ipaddress.ip_network(self.target, strict=False)
                first_host = str(network.network_address + 1)
                self.discover_servers(first_host, self.port)
            except Exception as e:
                print_error(f"Error in direct discovery: {e}")
                return
        else:
            # For each discovered host, try to get server information
            for host in discovered_hosts:
                self.get_target_info(host=host, port=self.port)
        
        # Remove duplicates and show results
        unique_servers = [list(x) for x in set(tuple(x) for x in self.result)]
        
        if len(self.result) > 0:
            print_success(f"Found {len(self.result)} OPC UA server(s)")
            print_table(TABLE_HEADER, *unique_servers)
            print('\r')
        else:
            print_error(f"Didn't find any OPC UA servers on network {self.target}")

    def command_export(self, file_path, *args, **kwargs):
        unique_servers = [list(x) for x in set(tuple(x) for x in self.result)]
        unique_servers = sorted(unique_servers)
        export_table(file_path, TABLE_HEADER, unique_servers) 