import os
import sys
import importlib
import logging
from typing import Dict, Optional, Any, List
from src.modules.clients.base import Base
from src import utils


class ClientManager:
    """Manages client instances following the module pattern"""
    
    def __init__(self):
        self.current_client = None
        self.clients: Dict[str, Base] = {}
        self.logger = logging.getLogger('client_manager')
        
        # Available client types with their module paths
        self.available_clients = {
            'bacnet': 'icssploit.clients.bacnet_client.BACnetClient',
            'modbus': 'icssploit.clients.modbus_client.ModbusClient',
            'modbus_tcp': 'icssploit.clients.modbus_tcp_client.ModbusTcpClient',
            's7': 'icssploit.clients.s7_client.S7Client',
            's7plus': 'icssploit.clients.s7plus_client.S7PlusClient',
            'opcua': 'icssploit.clients.opcua_client.OpcuaClient',
            'cip': 'icssploit.clients.cip_client.CipClient',
            'wdb2': 'icssploit.clients.wdb2_client.Wdb2Client',
            'zmq': 'icssploit.clients.zmq_client.ZMQClient'
        }
    
    def get_available_clients(self) -> List[str]:
        """Get list of available client types"""
        return list(self.available_clients.keys())
    
    def use_client(self, client_type: str, name: str = None, **kwargs):
        """Load and select a client (similar to use_module)"""
        if client_type not in self.available_clients:
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
                    'zmq': 'zmq'
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
            self.clients[name] = client
            self.current_client = client
            
            self.logger.info(f"Loaded {client_type} client: {name}")
            utils.print_success(f"Using {client_type} client: {name}")
            
        except Exception as e:
            self.logger.error(f"Failed to load client {client_type}: {e}")
            utils.print_error(f"Failed to load client {client_type}: {e}")
    
    def back(self):
        """Deselect current client (similar to module back)"""
        if self.current_client:
            utils.print_info(f"Deselected client: {self.current_client.name}")
        self.current_client = None
    
    def get_current_client(self) -> Optional[Base]:
        """Get currently active client"""
        return self.current_client
    
    def set_current_client(self, name: str) -> bool:
        """Set current client by name"""
        if name in self.clients:
            self.current_client = self.clients[name]
            utils.print_success(f"Current client set to: {name}")
            return True
        else:
            utils.print_error(f"Client not found: {name}")
            return False
    
    def list_clients(self) -> Dict[str, Dict[str, Any]]:
        """List all created clients with their information"""
        result = {}
        for name, client in self.clients.items():
            info = {
                'name': name,
                'type': client.__class__.__name__,
                'connected': client._connected if hasattr(client, '_connected') else False,
                'current': (client == self.current_client),
                'ip': getattr(client, '_address', 'Unknown'),
                'port': getattr(client, '_port', 'Unknown')
            }
            result[name] = info
        return result
    
    def connect_client(self, name: str) -> bool:
        """Connect a specific client"""
        if name not in self.clients:
            utils.print_error(f"Client not found: {name}")
            return False
        
        client = self.clients[name]
        try:
            if client.connect():
                utils.print_success(f"Connected client: {name}")
                return True
            else:
                utils.print_error(f"Failed to connect client: {name}")
                return False
        except Exception as e:
            utils.print_error(f"Error connecting client {name}: {e}")
            return False
    
    def disconnect_client(self, name: str) -> bool:
        """Disconnect a specific client"""
        if name not in self.clients:
            utils.print_error(f"Client not found: {name}")
            return False
        
        client = self.clients[name]
        try:
            if client.disconnect():
                utils.print_success(f"Disconnected client: {name}")
                return True
            else:
                utils.print_error(f"Failed to disconnect client: {name}")
                return False
        except Exception as e:
            utils.print_error(f"Error disconnecting client {name}: {e}")
            return False
    
    def remove_client(self, name: str) -> bool:
        """Remove a client"""
        if name not in self.clients:
            utils.print_error(f"Client not found: {name}")
            return False
        
        client = self.clients[name]
        
        # Disconnect if connected
        if hasattr(client, '_connected') and client._connected:
            client.disconnect()
        
        # Remove from current if it's the current client
        if self.current_client == client:
            self.current_client = None
        
        # Remove from clients dict
        del self.clients[name]
        utils.print_success(f"Removed client: {name}")
        return True
    
    def get_client_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a client"""
        if name not in self.clients:
            return None
        
        client = self.clients[name]
        info = {
            'name': name,
            'type': client.__class__.__name__,
            'connected': client._connected if hasattr(client, '_connected') else False,
            'current': (client == self.current_client),
            'ip': getattr(client, '_address', 'Unknown'),
            'port': getattr(client, '_port', 'Unknown')
        }
        
        # Add any additional attributes
        for attr in ['_timeout', '_device_type', '_socket_type', '_transport']:
            if hasattr(client, attr):
                info[attr[1:]] = getattr(client, attr)
        
        return info
    
    def execute_client_method(self, client_name: str, method_name: str, *args, **kwargs) -> Any:
        """Execute a method on a specific client"""
        if client_name not in self.clients:
            utils.print_error(f"Client not found: {client_name}")
            return None
        
        client = self.clients[client_name]
        if hasattr(client, method_name):
            method = getattr(client, method_name)
            try:
                return method(*args, **kwargs)
            except Exception as e:
                utils.print_error(f"Error executing {method_name} on {client_name}: {e}")
                return None
        else:
            utils.print_error(f"Method {method_name} not found on client {client_name}")
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
            help_text += f"Class: {client_class.__name__}\n\n"
            help_text += f"Description:\n{doc}\n\n"
            help_text += f"Available methods: {', '.join(methods)}"
            
            return help_text
            
        except Exception as e:
            return f"Error getting help for {client_type}: {e}" 