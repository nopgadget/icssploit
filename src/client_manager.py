#!/usr/bin/env python3
"""
Client Manager for ICSSploit
Manages client instances and provides unified interface for client operations
"""

import importlib
import logging
from typing import Dict, Optional, Any, List
from src.modules.clients.base import Base


class ClientManager:
    """Manages client instances and provides unified interface"""
    
    def __init__(self):
        self.clients: Dict[str, Base] = {}
        self.current_client: Optional[Base] = None
        self.logger = logging.getLogger('client_manager')
        
        # Available client types
        self.available_clients = {
            'bacnet': 'src.modules.clients.bacnet_client.BACnetClient',
            'modbus': 'src.modules.clients.modbus_client.ModbusClient',
            'modbus_tcp': 'src.modules.clients.modbus_tcp_client.ModbusTcpClient',
            's7': 'src.modules.clients.s7_client.S7Client',
            's7plus': 'src.modules.clients.s7plus_client.S7PlusClient',
            'opcua': 'src.modules.clients.opcua_client.OPCUAClient',
            'cip': 'src.modules.clients.cip_client.CipClient',
            'wdb2': 'src.modules.clients.wdb2_client.Wdb2Client',
            'zmq': 'src.modules.clients.zmq_client.ZMQClient',
            'cclink': 'src.modules.clients.cclink_client.CCLinkClient'
        }
    
    def get_available_clients(self) -> List[str]:
        """Get list of available client types"""
        return list(self.available_clients.keys())
    
    def use_client(self, client_type: str, name: str = None, **kwargs):
        """Load and select a client (similar to use_module)"""
        if client_type not in self.available_clients:
            from src import utils
            utils.print_error(f"Unknown client type: {client_type}")
            utils.print_info(f"Available types: {', '.join(self.get_available_clients())}")
            return
        
        try:
            # Import config to get default ports
            from src.config import DEFAULT_PORTS
            
            # Apply default port if not specified
            if 'port' not in kwargs:
                # Map client types to config keys
                port_mapping = {
                    'bacnet': 'bacnet',
                    'modbus': 'modbus',
                    'modbus_tcp': 'modbus',
                    's7': 's7comm',
                    's7plus': 's7comm',
                    'opcua': 'opcua',
                    'cip': 'ethernetip',
                    'wdb2': 'wdb2',
                    'zmq': 'zmq',
                    'cclink': 'cclink'
                }
                
                config_key = port_mapping.get(client_type)
                if config_key and config_key in DEFAULT_PORTS:
                    kwargs['port'] = DEFAULT_PORTS[config_key]
                    self.logger.info(f"Using default port {kwargs['port']} for {client_type} client")
            
            # Import the client class
            module_path, class_name = self.available_clients[client_type].rsplit('.', 1)
            module = importlib.import_module(module_path)
            client_class = getattr(module, class_name)
            
            # Create client instance with default name if not provided
            if name is None:
                name = f"{client_type}_client"
            
            # Create client instance
            client = client_class(name=name, **kwargs)
            
            # Set up options for the client (similar to modules)
            if hasattr(client_class, 'options'):
                client.options = client_class.options
            else:
                # Default options for clients
                client.options = ['target', 'port']
            
            # Set default values for options
            for option in client.options:
                if not hasattr(client, option):
                    if option == 'target':
                        setattr(client, option, '')
                    elif option == 'port':
                        setattr(client, option, kwargs.get('port', 0))
                    else:
                        setattr(client, option, '')
            
            self.clients[name] = client
            self.current_client = client
            
            self.logger.info(f"Loaded {client_type} client: {name}")
            from src import utils
            utils.print_success(f"Using {client_type} client: {name}")
            
        except Exception as e:
            self.logger.error(f"Failed to load client {client_type}: {e}")
            from src import utils
            utils.print_error(f"Failed to load client {client_type}: {e}")
    
    def back(self):
        """Deselect current client (similar to module back)"""
        if self.current_client:
            from src import utils
            utils.print_info(f"Deselected client: {self.current_client.name}")
        self.current_client = None
    
    def create_client(self, client_type: str, name: str, **kwargs) -> Optional[Base]:
        """
        Create a new client instance
        
        Args:
            client_type: Type of client (e.g., 'bacnet', 'modbus')
            name: Name for the client instance
            **kwargs: Additional arguments for client initialization
            
        Returns:
            Client instance or None if creation failed
        """
        try:
            if client_type not in self.available_clients:
                self.logger.error(f"Unknown client type: {client_type}")
                return None
            
            # Import config to get default ports
            from src.config import DEFAULT_PORTS
            
            # Apply default port if not specified
            if 'port' not in kwargs:
                # Map client types to config keys
                port_mapping = {
                    'bacnet': 'bacnet',
                    'modbus': 'modbus',
                    'modbus_tcp': 'modbus',
                    's7': 's7comm',
                    's7plus': 's7comm',
                    'opcua': 'opcua',
                    'cip': 'ethernetip',
                    'wdb2': 'wdb2',
                    'zmq': 'zmq',
                    'cclink': 'cclink'
                }
                
                config_key = port_mapping.get(client_type)
                if config_key and config_key in DEFAULT_PORTS:
                    kwargs['port'] = DEFAULT_PORTS[config_key]
                    self.logger.info(f"Using default port {kwargs['port']} for {client_type} client")
            
            # Import the client class
            module_path, class_name = self.available_clients[client_type].rsplit('.', 1)
            module = importlib.import_module(module_path)
            client_class = getattr(module, class_name)
            
            # Create client instance
            client = client_class(name=name, **kwargs)
            self.clients[name] = client
            self.current_client = client
            
            self.logger.info(f"Created {client_type} client: {name}")
            return client
            
        except Exception as e:
            self.logger.error(f"Failed to create client {client_type}: {e}")
            return None
    
    def get_client(self, name: str) -> Optional[Base]:
        """Get client by name"""
        return self.clients.get(name)
    
    def get_current_client(self) -> Optional[Base]:
        """Get currently active client"""
        return self.current_client
    
    def set_current_client(self, name: str) -> bool:
        """Set current client by name"""
        if name in self.clients:
            self.current_client = self.clients[name]
            return True
        return False
    
    def list_clients(self) -> Dict[str, Dict[str, Any]]:
        """List all client instances with their information"""
        result = {}
        for name, client in self.clients.items():
            client_info = {
                'type': type(client).__name__,
                'connected': getattr(client, '_connected', False),
                'current': (client == self.current_client)
            }
            
            # Add client-specific information
            if hasattr(client, '_ip'):
                client_info['ip'] = getattr(client, '_ip', 'Unknown')
            if hasattr(client, '_port'):
                client_info['port'] = getattr(client, '_port', 'Unknown')
            
            result[name] = client_info
        
        return result
    
    def connect_client(self, name: str) -> bool:
        """Connect a client by name"""
        client = self.get_client(name)
        if client and hasattr(client, 'connect'):
            try:
                return client.connect()
            except Exception as e:
                self.logger.error(f"Failed to connect client {name}: {e}")
                return False
        return False
    
    def disconnect_client(self, name: str) -> bool:
        """Disconnect a client by name"""
        client = self.get_client(name)
        if client and hasattr(client, 'disconnect'):
            try:
                client.disconnect()
                return True
            except Exception as e:
                self.logger.error(f"Failed to disconnect client {name}: {e}")
                return False
        return False
    
    def remove_client(self, name: str) -> bool:
        """Remove a client instance"""
        if name in self.clients:
            # Disconnect if connected
            self.disconnect_client(name)
            
            # Remove from clients dict
            client = self.clients.pop(name)
            
            # Update current client if needed
            if self.current_client == client:
                self.current_client = None
                if self.clients:
                    self.current_client = next(iter(self.clients.values()))
            
            self.logger.info(f"Removed client: {name}")
            return True
        return False
    
    def execute_client_method(self, client_name: str, method_name: str, *args, **kwargs) -> Any:
        """Execute a method on a specific client"""
        client = self.get_client(client_name)
        if client and hasattr(client, method_name):
            try:
                method = getattr(client, method_name)
                return method(*args, **kwargs)
            except Exception as e:
                self.logger.error(f"Failed to execute {method_name} on client {client_name}: {e}")
                return None
        else:
            self.logger.error(f"Client {client_name} not found or method {method_name} not available")
            return None
    
    def get_client_help(self, client_type: str) -> str:
        """Get help information for a client type"""
        if client_type not in self.available_clients:
            return f"Unknown client type: {client_type}"
        
        try:
            module_path, class_name = self.available_clients[client_type].rsplit('.', 1)
            module = importlib.import_module(module_path)
            client_class = getattr(module, class_name)
            
            # Get docstring
            doc = client_class.__doc__ or "No documentation available"
            
            # Get available methods
            methods = [method for method in dir(client_class) 
                      if not method.startswith('_') and callable(getattr(client_class, method))]
            
            help_text = f"Client Type: {client_type}\n"
            help_text += f"Class: {class_name}\n\n"
            help_text += f"Documentation:\n{doc}\n\n"
            help_text += f"Available Methods:\n"
            for method in sorted(methods):
                help_text += f"  - {method}\n"
            
            return help_text
            
        except Exception as e:
            return f"Error getting help for {client_type}: {e}"
    
    def get_client_info(self, name: str) -> Dict[str, Any]:
        """Get detailed information about a client"""
        client = self.get_client(name)
        if not client:
            return {}
        
        info = {
            'name': name,
            'type': type(client).__name__,
            'connected': getattr(client, '_connected', False),
            'current': (client == self.current_client)
        }
        
        # Add client-specific attributes
        for attr in ['_ip', '_port', '_device_id', '_timeout']:
            if hasattr(client, attr):
                info[attr[1:]] = getattr(client, attr)
        
        return info
    
    def cleanup_all_clients(self):
        """Disconnect and cleanup all active clients"""
        if not self.clients:
            return
        
        self.logger.info("Cleaning up active clients...")
        for name, client in list(self.clients.items()):
            try:
                # Disconnect if connected
                if hasattr(client, '_connected') and client._connected:
                    self.logger.info(f"Disconnecting client: {name}")
                    if hasattr(client, 'disconnect'):
                        client.disconnect()
                    else:
                        client._connected = False
                        if hasattr(client, '_connection') and client._connection:
                            try:
                                client._connection.close()
                            except:
                                pass
                            client._connection = None
                elif hasattr(client, 'disconnect'):
                    # Force disconnect even if not marked as connected (OPC UA case)
                    self.logger.info(f"Force disconnecting client: {name}")
                    try:
                        client.disconnect()
                    except Exception as disconnect_error:
                        self.logger.warning(f"Force disconnect failed for {name}: {disconnect_error}")
                
                # Clean up OPC UA specific attributes aggressively
                if hasattr(client, '_client') and client._client:
                    try:
                        # Force cleanup of OPC UA client internals
                        opcua_client = client._client
                        
                        # Try to force close socket connections
                        if hasattr(opcua_client, '_socket') and opcua_client._socket:
                            opcua_client._socket.close()
                        
                        # Try to stop any background threads
                        if hasattr(opcua_client, '_thread') and opcua_client._thread:
                            opcua_client._thread = None
                            
                        # Clear any internal references
                        if hasattr(opcua_client, '_subscription_manager'):
                            opcua_client._subscription_manager = None
                            
                        client._client = None
                    except:
                        pass
                            
            except Exception as e:
                self.logger.warning(f"Error cleaning up client {name}: {e}")
        
        # Clear all clients
        self.clients.clear()
        self.current_client = None
        self.logger.info("All clients cleaned up") 