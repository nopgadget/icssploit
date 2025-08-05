#!/usr/bin/env python3
"""
Client Manager for ICSSploit
Manages client instances and provides unified interface for client operations
"""

import importlib
import logging
from typing import Dict, Optional, Any, List
from src.clients.base import Base


class ClientManager:
    """Manages client instances and provides unified interface"""
    
    def __init__(self):
        self.clients: Dict[str, Base] = {}
        self.current_client: Optional[Base] = None
        self.logger = logging.getLogger('client_manager')
        
        # Available client types
        self.available_clients = {
            'bacnet': 'icssploit.clients.bacnet_client.BACnetClient',
            'modbus': 'icssploit.clients.modbus_client.ModbusClient',
            'modbus_tcp': 'icssploit.clients.modbus_tcp_client.ModbusTcpClient',
            's7': 'icssploit.clients.s7_client.S7Client',
            's7plus': 'icssploit.clients.s7plus_client.S7PlusClient',
            'opcua': 'icssploit.clients.opcua_client.OpcuaClient',
            'cip': 'icssploit.clients.cip_client.CipClient',
            'wdb2': 'icssploit.clients.wdb2_client.Wdb2Client'
        }
    
    def get_available_clients(self) -> List[str]:
        """Get list of available client types"""
        return list(self.available_clients.keys())
    
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
                    'wdb2': 'wdb2'
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