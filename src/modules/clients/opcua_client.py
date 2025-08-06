#!/usr/bin/env python3
"""
OPC UA Client for ICSSploit
A Python client to interact with OPC UA servers using python-opcua
"""

import asyncio
import sys
import time
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from dataclasses import dataclass
from enum import Enum
from src.modules.clients.base import Base

# Import python-opcua components
try:
    from opcua import Client, ua
    from opcua.common.subscription import Subscription
    from opcua.common.node import Node
    OPCUA_AVAILABLE = True
except ImportError as e:
    print(f"Error: python-opcua not installed or import failed: {e}")
    print("Please install with: pip install opcua")
    OPCUA_AVAILABLE = False


class OPCUASecurityMode(Enum):
    """OPC-UA Security Modes"""
    NONE = "None"
    SIGN = "Sign"
    SIGN_AND_ENCRYPT = "SignAndEncrypt"


class OPCUASecurityPolicy(Enum):
    """OPC-UA Security Policies"""
    NONE = "None"
    BASIC128RSA15 = "Basic128Rsa15"
    BASIC256 = "Basic256"
    BASIC256SHA256 = "Basic256Sha256"
    AES128_SHA256_RSAOAEP = "Aes128_Sha256_RsaOaep"
    AES256_SHA256_RSAPSS = "Aes256_Sha256_RsaPss"


@dataclass
class OPCUAServer:
    """Represents an OPC-UA server"""
    url: str
    name: str
    application_uri: str
    product_uri: str
    server_uri: str
    security_policy_uri: str
    security_mode: str
    transport_profile_uri: str


@dataclass
class OPCUANode:
    """Represents an OPC-UA node"""
    node_id: str
    browse_name: str
    display_name: str
    node_class: str
    data_type: Optional[str] = None
    value: Optional[Any] = None
    access_level: Optional[int] = None
    user_access_level: Optional[int] = None


class OPCUAClient(Base):
    """OPC UA client for ICSSploit"""
    
    # Client options (similar to module options)
    options = ['target', 'port', 'timeout', 'security_policy', 'security_mode', 'username', 'password']
    
    def __init__(self, name: str, target: str = 'localhost', port: int = 4840, timeout: int = 4,
                 security_policy: str = "None", security_mode: str = "None",
                 username: str = None, password: str = None,
                 certificate_path: str = None, private_key_path: str = None):
        """
        Initialize OPC UA client
        
        Args:
            name: Name of this target
            target: OPC UA server IP address
            port: OPC UA server port (default: 4840)
            timeout: Connection timeout
            security_policy: Security policy
            security_mode: Security mode
            username: Username for authentication
            password: Password for authentication
            certificate_path: Path to client certificate
            private_key_path: Path to client private key
        """
        super(OPCUAClient, self).__init__(name=name)
        self._target = target
        self._port = port
        self._timeout = timeout
        self._security_policy = security_policy
        self._security_mode = security_mode
        self._username = username
        self._password = password
        self._certificate_path = certificate_path
        self._private_key_path = private_key_path
        
        # OPC-UA client object
        self._client = None
        self._connected = False
        self._subscriptions = {}
        
        if not OPCUA_AVAILABLE:
            self.logger.error("python-opcua library not available. Please install with: pip install opcua")
    
    @property
    def target(self):
        """Get target IP address"""
        return self._target
        
    @target.setter
    def target(self, value):
        """Set target IP address"""
        self._target = value
        
    @property
    def port(self):
        """Get port number"""
        return self._port
        
    @port.setter
    def port(self, value):
        """Set port number"""
        self._port = int(value)
        
    @property
    def timeout(self):
        """Get timeout value"""
        return self._timeout
        
    @timeout.setter
    def timeout(self, value):
        """Set timeout value"""
        self._timeout = int(value)
    
    @property
    def security_policy(self):
        """Get security policy"""
        return self._security_policy
        
    @security_policy.setter
    def security_policy(self, value):
        """Set security policy"""
        self._security_policy = value
        
    @property
    def security_mode(self):
        """Get security mode"""
        return self._security_mode
        
    @security_mode.setter
    def security_mode(self, value):
        """Set security mode"""
        self._security_mode = value
        
    @property
    def username(self):
        """Get username"""
        return self._username
        
    @username.setter
    def username(self, value):
        """Set username"""
        self._username = value
        
    @property
    def password(self):
        """Get password"""
        return self._password
        
    @password.setter
    def password(self, value):
        """Set password"""
        self._password = value
    
    @property
    def url(self):
        """Get constructed OPC UA URL"""
        return f"opc.tcp://{self._target}:{self._port}"
    
    def connect(self) -> bool:
        """Connect to OPC UA server"""
        try:
            if not self._client:
                # Create client
                self._client = Client(url=self.url, timeout=self._timeout)
                
                # Set security if specified
                if self._security_policy != "None" or self._security_mode != "None":
                    if self._certificate_path and self._private_key_path:
                        self._client.set_security_string(f"{self._security_policy},{self._security_mode},{self._certificate_path},{self._private_key_path}")
                    else:
                        self.logger.warning("Security policy/mode specified but no certificate provided")
                
                # Set credentials if provided
                if self._username:
                    self._client.set_user(self._username)
                if self._password:
                    self._client.set_password(self._password)
            
            self._client.connect()
            self._connected = True
            self.logger.info(f"Connected to OPC UA server at {self.url}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to OPC UA server: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from OPC UA server"""
        if self._client:
            try:
                # Only disconnect if we think we're connected
                if self._connected:
                    self._client.disconnect()
                    self.logger.info("Disconnected from OPC UA server")
                
                # Always reset state regardless of connection status
                self._connected = False
                
                # Force cleanup of the client object to prevent hanging
                try:
                    # Try to force close any remaining connections
                    if hasattr(self._client, '_socket') and self._client._socket:
                        self._client._socket.close()
                except:
                    pass
                
                try:
                    # Clean up any subscription handlers
                    if hasattr(self._client, '_subscription_callbacks'):
                        self._client._subscription_callbacks.clear()
                except:
                    pass
                
                # Completely remove the client reference
                self._client = None
                
            except Exception as e:
                self.logger.error(f"Error during disconnect: {e}")
                # Force reset state even if disconnect failed
                self._connected = False
                self._client = None
        
        # Also clear subscriptions dict
        if hasattr(self, '_subscriptions'):
            self._subscriptions.clear()
    
    def discover_servers(self) -> List[OPCUAServer]:
        """Discover OPC-UA servers on the network"""
        servers = []
        
        if not self.connect():
            return servers
        
        try:
            self.logger.info("Discovering OPC-UA servers...")
            
            # Find servers
            found_servers = self._client.find_servers()
            
            for server_info in found_servers:
                server = OPCUAServer(
                    url=server_info.ApplicationUri,
                    name=server_info.ApplicationName.Text,
                    application_uri=server_info.ApplicationUri,
                    product_uri=server_info.ProductUri,
                    server_uri=server_info.ServerUri,
                    security_policy_uri=server_info.SecurityPolicyUri,
                    security_mode=str(server_info.SecurityMode),
                    transport_profile_uri=server_info.TransportProfileUri
                )
                servers.append(server)
                self.logger.info(f"Found server: {server.name} ({server.url})")
            
        except Exception as e:
            self.logger.error(f"Error discovering servers: {e}")
        finally:
            self.disconnect()
        
        return servers
    
    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Get server endpoints"""
        endpoints = []
        
        if not self.connect():
            return endpoints
        
        try:
            self.logger.info("Getting server endpoints...")
            
            server_endpoints = self._client.get_endpoints()
            
            for endpoint in server_endpoints:
                endpoint_info = {
                    'endpoint_url': endpoint.EndpointUrl,
                    'security_policy_uri': endpoint.SecurityPolicyUri,
                    'security_mode': str(endpoint.SecurityMode),
                    'transport_profile_uri': endpoint.TransportProfileUri,
                    'user_token_policies': []
                }
                
                for policy in endpoint.UserIdentityTokens:
                    endpoint_info['user_token_policies'].append({
                        'policy_id': policy.PolicyId,
                        'token_type': str(policy.TokenType),
                        'issued_token_type': policy.IssuedTokenType,
                        'issuer_endpoint_url': policy.IssuerEndpointUrl,
                        'security_policy_uri': policy.SecurityPolicyUri
                    })
                
                endpoints.append(endpoint_info)
                self.logger.info(f"Endpoint: {endpoint.EndpointUrl}")
            
        except Exception as e:
            self.logger.error(f"Error getting endpoints: {e}")
        finally:
            self.disconnect()
        
        return endpoints
    
    def browse_nodes(self, node_id: str = "i=84", max_results: int = 100) -> List[OPCUANode]:
        """Browse nodes starting from the specified node ID"""
        nodes = []
        
        # Check if we were already connected
        was_connected = self._connected
        
        if not self.connect():
            return nodes
        
        try:
            self.logger.info(f"Browsing nodes starting from {node_id}...")
            
            # Get the starting node
            start_node = self._client.get_node(node_id)
            
            # Browse the node
            children = start_node.get_children()
            
            for child in children[:max_results]:
                try:
                    # Get node attributes
                    browse_name = child.get_browse_name()
                    display_name = child.get_display_name()
                    node_class = str(child.get_node_class())
                    
                    # Try to get data type
                    data_type = None
                    try:
                        data_type_node = child.get_data_type()
                        data_type = data_type_node.get_browse_name().Name
                    except:
                        pass
                    
                    # Try to get value
                    value = None
                    try:
                        value = child.get_value()
                    except:
                        pass
                    
                    # Try to get access levels
                    access_level = None
                    user_access_level = None
                    try:
                        access_level = child.get_access_level()
                        user_access_level = child.get_user_access_level()
                    except:
                        pass
                    
                    node = OPCUANode(
                        node_id=str(child.nodeid),
                        browse_name=browse_name.Name,
                        display_name=display_name.Text,
                        node_class=node_class,
                        data_type=data_type,
                        value=value,
                        access_level=access_level,
                        user_access_level=user_access_level
                    )
                    nodes.append(node)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing child node: {e}")
                    continue
            
            self.logger.info(f"Found {len(nodes)} nodes")
            
        except Exception as e:
            self.logger.error(f"Error browsing nodes: {e}")
        finally:
            # Only disconnect if we made the connection ourselves
            if not was_connected:
                self.disconnect()
        
        return nodes
    
    def read_node(self, node_id: str) -> Optional[OPCUANode]:
        """Read a single node"""
        if not self.connect():
            return None
        
        try:
            self.logger.info(f"Reading node {node_id}...")
            
            node = self._client.get_node(node_id)
            
            # Get node attributes
            browse_name = node.get_browse_name()
            display_name = node.get_display_name()
            node_class = str(node.get_node_class())
            
            # Try to get data type
            data_type = None
            try:
                data_type_node = node.get_data_type()
                data_type = data_type_node.get_browse_name().Name
            except:
                pass
            
            # Try to get value
            value = None
            try:
                value = node.get_value()
            except:
                pass
            
            # Try to get access levels
            access_level = None
            user_access_level = None
            try:
                access_level = node.get_access_level()
                user_access_level = node.get_user_access_level()
            except:
                pass
            
            opcua_node = OPCUANode(
                node_id=str(node.nodeid),
                browse_name=browse_name.Name,
                display_name=display_name.Text,
                node_class=node_class,
                data_type=data_type,
                value=value,
                access_level=access_level,
                user_access_level=user_access_level
            )
            
            self.logger.info(f"Node read successfully: {opcua_node.browse_name}")
            return opcua_node
            
        except Exception as e:
            self.logger.error(f"Error reading node {node_id}: {e}")
            return None
        finally:
            self.disconnect()
    
    def read_nodes(self, node_ids: List[str]) -> List[Optional[OPCUANode]]:
        """Read multiple nodes in one operation"""
        nodes = []
        
        if not self.connect():
            return [None] * len(node_ids)
        
        try:
            self.logger.info(f"Reading {len(node_ids)} nodes...")
            
            # Get node objects
            node_objects = [self._client.get_node(node_id) for node_id in node_ids]
            
            # Read values in batch
            values = self._client.get_values(node_objects)
            
            for i, node_obj in enumerate(node_objects):
                try:
                    # Get node attributes
                    browse_name = node_obj.get_browse_name()
                    display_name = node_obj.get_display_name()
                    node_class = str(node_obj.get_node_class())
                    
                    # Try to get data type
                    data_type = None
                    try:
                        data_type_node = node_obj.get_data_type()
                        data_type = data_type_node.get_browse_name().Name
                    except:
                        pass
                    
                    # Get value from batch read
                    value = values[i] if i < len(values) else None
                    
                    # Try to get access levels
                    access_level = None
                    user_access_level = None
                    try:
                        access_level = node_obj.get_access_level()
                        user_access_level = node_obj.get_user_access_level()
                    except:
                        pass
                    
                    opcua_node = OPCUANode(
                        node_id=str(node_obj.nodeid),
                        browse_name=browse_name.Name,
                        display_name=display_name.Text,
                        node_class=node_class,
                        data_type=data_type,
                        value=value,
                        access_level=access_level,
                        user_access_level=user_access_level
                    )
                    nodes.append(opcua_node)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing node {node_ids[i]}: {e}")
                    nodes.append(None)
            
            self.logger.info(f"Read {len([n for n in nodes if n is not None])} nodes successfully")
            
        except Exception as e:
            self.logger.error(f"Error reading nodes: {e}")
            nodes = [None] * len(node_ids)
        finally:
            self.disconnect()
        
        return nodes
    
    def write_node(self, node_id: str, value: Any) -> bool:
        """Write value to a node"""
        if not self.connect():
            return False
        
        try:
            self.logger.info(f"Writing value {value} to node {node_id}...")
            
            node = self._client.get_node(node_id)
            node.set_value(value)
            
            self.logger.info("Node write successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Error writing to node {node_id}: {e}")
            return False
        finally:
            self.disconnect()
    
    def write_nodes(self, node_ids: List[str], values: List[Any]) -> List[bool]:
        """Write values to multiple nodes in one operation"""
        results = []
        
        if not self.connect():
            return [False] * len(node_ids)
        
        try:
            self.logger.info(f"Writing values to {len(node_ids)} nodes...")
            
            # Get node objects
            node_objects = [self._client.get_node(node_id) for node_id in node_ids]
            
            # Write values in batch
            self._client.set_values(node_objects, values)
            
            results = [True] * len(node_ids)
            self.logger.info("Batch write successful")
            
        except Exception as e:
            self.logger.error(f"Error writing nodes: {e}")
            results = [False] * len(node_ids)
        finally:
            self.disconnect()
        
        return results
    
    def call_method(self, object_node_id: str, method_node_id: str, 
                   arguments: List[Any] = None) -> Optional[Any]:
        """Call a method on an object"""
        if not self.connect():
            return None
        
        try:
            self.logger.info(f"Calling method {method_node_id} on object {object_node_id}...")
            
            object_node = self._client.get_node(object_node_id)
            method_node = self._client.get_node(method_node_id)
            
            if arguments is None:
                arguments = []
            
            result = object_node.call_method(method_node, *arguments)
            
            self.logger.info("Method call successful")
            return result
            
        except Exception as e:
            self.logger.error(f"Error calling method: {e}")
            return None
        finally:
            self.disconnect()
    
    def test_connection(self) -> bool:
        """Test connection to the OPC-UA server"""
        try:
            if not self.connect():
                return False
            
            # Try to read the root node
            root_node = self._client.get_root_node()
            root_node.get_browse_name()
            
            self.logger.info("Connection test successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
        finally:
            self.disconnect()
    
    def get_server_info(self) -> Optional[Dict[str, Any]]:
        """Get server information"""
        if not self.connect():
            return None
        
        try:
            self.logger.info("Getting server information...")
            
            # Get server node
            server_node = self._client.get_server_node()
            
            # Get basic server information that's actually available
            server_info = {
                'server_name': 'Unknown',
                'server_uri': self.url,
                'application_uri': 'Unknown',
                'product_uri': 'Unknown',
                'software_version': 'Unknown',
                'build_number': 'Unknown',
                'build_date': 'Unknown'
            }
            
            try:
                # Try to get server name from server node
                server_info['server_name'] = server_node.get_browse_name().Name
            except:
                pass
                
            try:
                # Try to get server status and other available info from server node children
                server_children = server_node.get_children()
                for child in server_children:
                    try:
                        browse_name = child.get_browse_name().Name.lower()
                        if 'status' in browse_name:
                            # Try to read server status information
                            status_children = child.get_children()
                            for status_child in status_children:
                                status_name = status_child.get_browse_name().Name.lower()
                                if 'buildinfo' in status_name:
                                    # Try to get build information
                                    build_children = status_child.get_children()
                                    for build_child in build_children:
                                        build_browse_name = build_child.get_browse_name().Name.lower()
                                        try:
                                            value = build_child.get_value()
                                            if 'productname' in build_browse_name:
                                                server_info['server_name'] = str(value)
                                            elif 'productUri' in build_browse_name:
                                                server_info['product_uri'] = str(value)
                                            elif 'softwareversion' in build_browse_name:
                                                server_info['software_version'] = str(value)
                                            elif 'buildnumber' in build_browse_name:
                                                server_info['build_number'] = str(value)
                                            elif 'builddate' in build_browse_name:
                                                server_info['build_date'] = str(value)
                                        except:
                                            continue
                    except:
                        continue
            except:
                pass
            
            # Try to get endpoints for additional server information
            try:
                endpoints = self._client.get_endpoints()
                if endpoints:
                    endpoint = endpoints[0]  # Use first endpoint
                    if hasattr(endpoint, 'Server') and hasattr(endpoint.Server, 'ApplicationUri'):
                        server_info['application_uri'] = endpoint.Server.ApplicationUri
                    if hasattr(endpoint, 'Server') and hasattr(endpoint.Server, 'ProductUri'):
                        server_info['product_uri'] = endpoint.Server.ProductUri
            except:
                pass
            
            self.logger.info("Server information retrieved successfully")
            return server_info
            
        except Exception as e:
            self.logger.error(f"Error getting server info: {e}")
            return None
        finally:
            self.disconnect()
    
    def get_target_info(self) -> Tuple[str, str, str, str, str, str]:
        """
        Get target device information
        
        Returns:
            Tuple of (server_name, server_uri, application_uri, product_uri, software_version, build_number)
        """
        try:
            info = self.get_server_info()
            if info:
                return (
                    info.get('server_name', 'Unknown'),
                    info.get('server_uri', 'Unknown'),
                    info.get('application_uri', 'Unknown'),
                    info.get('product_uri', 'Unknown'),
                    info.get('software_version', 'Unknown'),
                    str(info.get('build_number', 'Unknown'))
                )
            else:
                return ('Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown')
            
        except Exception as e:
            self.logger.error(f"Error getting target info: {e}")
            return ('Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown')
    
    def enumerate_device(self) -> Dict[str, List[OPCUANode]]:
        """
        Enumerate device nodes by browsing common starting points
        
        Returns:
            Dictionary mapping browse paths to lists of nodes
        """
        result = {}
        
        # Common starting points for browsing
        browse_paths = {
            'root': 'i=84',
            'objects': 'i=85',
            'types': 'i=86',
            'views': 'i=87',
            'methods': 'i=88'
        }
        
        for path_name, node_id in browse_paths.items():
            try:
                nodes = self.browse_nodes(node_id, max_results=50)
                if nodes:
                    result[path_name] = nodes
            except Exception as e:
                self.logger.debug(f"Error browsing {path_name}: {e}")
        
        return result
    
    def check_permissions(self) -> Dict[str, bool]:
        """
        Check read/write permissions for different node types
        
        Returns:
            Dictionary mapping permission types to read/write permission status
        """
        permissions = {}
        
        # Test read permissions on common nodes
        test_nodes = [
            ('root_read', 'i=84'),
            ('objects_read', 'i=85'),
            ('types_read', 'i=86'),
            ('server_read', 'i=2253')
        ]
        
        for perm_name, node_id in test_nodes:
            try:
                node = self.read_node(node_id)
                permissions[perm_name] = node is not None
            except Exception as e:
                permissions[perm_name] = False
        
        # Test write permissions (be careful!)
        write_test_nodes = [
            ('server_write', 'i=2253')  # Server node - usually read-only
        ]
        
        for perm_name, node_id in write_test_nodes:
            try:
                # Try to write a test value (this might fail safely)
                success = self.write_node(node_id, "test")
                permissions[perm_name] = success
            except Exception as e:
                permissions[perm_name] = False
        
        return permissions
    
    def brute_force_credentials(self, password_wordlist_path: str, 
                              username_wordlist_path: str = None,
                              delay: float = 1.0) -> List[Dict[str, str]]:
        """Brute force OPC-UA server credentials"""
        valid_credentials = []
        
        try:
            # Load password wordlist
            with open(password_wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"Loaded {len(passwords)} passwords from wordlist")
            
            # Load username wordlist if provided
            usernames = ['admin', 'root', 'user', 'operator']  # Default usernames
            if username_wordlist_path:
                try:
                    with open(username_wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        usernames = [line.strip() for line in f if line.strip()]
                    self.logger.info(f"Loaded {len(usernames)} usernames from wordlist")
                except Exception as e:
                    self.logger.warning(f"Failed to load username wordlist: {e}")
            
            total_attempts = len(usernames) * len(passwords)
            current_attempt = 0
            
            self.logger.info(f"Starting brute force attack with {total_attempts} total attempts")
            self.logger.info(f"Delay between attempts: {delay}s")
            
            for username in usernames:
                for password in passwords:
                    current_attempt += 1
                    
                    self.logger.info(f"Attempt {current_attempt}/{total_attempts}: {username}:{password}")
                    
                    try:
                        # Create a new client instance for each attempt
                        test_client = Client(url=self.url, timeout=self._timeout)
                        test_client.set_user(username)
                        test_client.set_password(password)
                        
                        # Try to connect
                        test_client.connect()
                        
                        # If we get here, authentication was successful
                        self.logger.info(f"✅ SUCCESS: Valid credentials found - {username}:{password}")
                        valid_credentials.append({
                            'username': username,
                            'password': password,
                            'attempt': current_attempt
                        })
                        
                        # Test if we can actually read data
                        try:
                            root_node = test_client.get_root_node()
                            root_node.get_browse_name()
                            self.logger.info(f"✅ Confirmed access - can read server data")
                        except Exception as e:
                            self.logger.warning(f"⚠️ Authentication succeeded but no data access: {e}")
                        
                        test_client.disconnect()
                        
                    except Exception as e:
                        # Authentication failed
                        self.logger.debug(f"❌ Failed: {username}:{password} - {str(e)[:100]}")
                    
                    # Delay between attempts to avoid overwhelming the server
                    if delay > 0:
                        time.sleep(delay)
            
            if valid_credentials:
                self.logger.info(f"🎉 Brute force completed! Found {len(valid_credentials)} valid credential(s)")
                for cred in valid_credentials:
                    self.logger.info(f"  Username: {cred['username']}, Password: {cred['password']} (attempt #{cred['attempt']})")
            else:
                self.logger.info("❌ No valid credentials found")
            
            return valid_credentials
            
        except Exception as e:
            self.logger.error(f"Error during brute force attack: {e}")
            return valid_credentials 