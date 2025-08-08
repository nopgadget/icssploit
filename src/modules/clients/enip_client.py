#!/usr/bin/env python3
"""
ENIP Client for ICSSploit
A Python client to interact with Ethernet/IP devices
Based on the ENIP protocol specification and existing implementations
"""

import socket
import struct
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum
from dataclasses import dataclass
from src.modules.clients.base import Base
from src.protocols.enip import *


class ENIPCommand(Enum):
    """Ethernet/IP commands"""
    NOP = 0x0000
    LIST_SERVICES = 0x0004
    LIST_IDENTITY = 0x0063
    LIST_INTERFACES = 0x0064
    REGISTER_SESSION = 0x0065
    UNREGISTER_SESSION = 0x0066
    SEND_RR_DATA = 0x006f
    SEND_UNIT_DATA = 0x0070
    INDICATE_STATUS = 0x0072
    CANCEL = 0x0073


class ENIPStatus(Enum):
    """Ethernet/IP status codes"""
    SUCCESS = 0x00000000
    INVALID_COMMAND = 0x00000001
    INSUFFICIENT_MEMORY = 0x00000002
    INCORRECT_DATA = 0x00000003
    INVALID_SESSION_HANDLE = 0x0064
    INVALID_LENGTH = 0x0065
    UNSUPPORTED_PROTOCOL_VERSION = 0x0069


class ENIPItemType(Enum):
    """Ethernet/IP item types"""
    NULL_ADDRESS_ITEM = 0x0000
    LIST_IDENTITY_RESPONSE = 0x000c
    CIP_SECURITY_INFORMATION = 0x0086
    CONNECTED_ADDRESS_ITEM = 0x00a1
    CONNECTED_DATA_ITEM = 0x00b1
    UNCONNECTED_DATA_ITEM = 0x00b2
    LIST_SERVICES_RESPONSE = 0x0100
    SOCKET_ADDRESS_INFO_O_TO_T = 0x8000
    SOCKET_ADDRESS_INFO_T_TO_O = 0x8001
    SEQUENCED_ADDRESS_ITEM = 0x8002
    UNCONNECTED_MESSAGE_OVER_UDP = 0x8003


@dataclass
class ENIPDevice:
    """Represents an Ethernet/IP device"""
    ip_address: str
    port: int = 44818
    product_name: str = ""
    device_type: str = ""
    vendor_id: int = 0
    vendor_name: str = ""
    revision: str = ""
    serial_number: str = ""
    session_handle: int = 0


class ENIPClient(Base):
    """Ethernet/IP client for ICSSploit"""

    # Client options (similar to module options)
    options = ['target', 'port', 'timeout', 'session_timeout', 'retry_count']

    def __init__(self, name: str, target: str = '', port: int = 44818,
                 timeout: int = 2, session_timeout: int = 30, retry_count: int = 3):
        """
        Initialize ENIP client
        
        Args:
            name: Name of this target
            target: Target ENIP device IP
            port: ENIP port (default: 44818)
            timeout: Socket timeout (default: 2)
            session_timeout: Session timeout in seconds (default: 30)
            retry_count: Number of retries for failed operations (default: 3)
        """
        super(ENIPClient, self).__init__(name=name)
        self._target = target
        self._port = port
        self._timeout = timeout
        self._session_timeout = session_timeout
        self._retry_count = retry_count
        self._connection = None
        self._connected = False
        self._session_handle = 0
        self._session_start_time = 0
        self._sequence_number = 0
        
        # Initialize logging
        self.logger = self.get_logger()
        
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
        if value == '' or value is None:
            raise ValueError("Port cannot be empty")
        self._port = int(value)
        
    @property
    def timeout(self):
        """Get timeout value"""
        return self._timeout
        
    @timeout.setter
    def timeout(self, value):
        """Set timeout value"""
        if value == '' or value is None:
            raise ValueError("Timeout cannot be empty")
        self._timeout = int(value)
        
    @property
    def session_timeout(self):
        """Get session timeout value"""
        return self._session_timeout
        
    @session_timeout.setter
    def session_timeout(self, value):
        """Set session timeout value"""
        if value == '' or value is None:
            raise ValueError("Session timeout cannot be empty")
        self._session_timeout = int(value)
        
    @property
    def retry_count(self):
        """Get retry count"""
        return self._retry_count
        
    @retry_count.setter
    def retry_count(self, value):
        """Set retry count"""
        if value == '' or value is None:
            raise ValueError("Retry count cannot be empty")
        self._retry_count = int(value)

    def connect(self) -> bool:
        """
        Connect to the ENIP device and register session
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            if self._connected and self._connection:
                self.logger.info("Already connected")
                return True
                
            self.logger.info(f"Connecting to ENIP device at {self._target}:{self._port}")
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((self._target, self._port))
            self._connection = sock
            self._connected = True
            
            # Register session
            if self._register_session():
                self._session_start_time = time.time()
                self.logger.info(f"Successfully connected to ENIP device at {self._target}:{self._port}")
                return True
            else:
                self.disconnect()
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to connect to ENIP device: {e}")
            self._connected = False
            return False

    def disconnect(self):
        """Disconnect from the ENIP device and unregister session"""
        try:
            if self._connected and self._session_handle:
                self._unregister_session()
                
            if self._connection:
                self._connection.close()
                self._connection = None
                self._connected = False
                self._session_handle = 0
                self.logger.info("Disconnected from ENIP device")
        except Exception as e:
            self.logger.error(f"Error disconnecting: {e}")

    def _register_session(self) -> bool:
        """
        Register a session with the ENIP device
        
        Returns:
            bool: True if registration successful, False otherwise
        """
        try:
            # Create register session packet
            packet = ENIPHeader(Command=ENIPCommand.REGISTER_SESSION.value) / RegisterSession()
            
            response = self.send_receive_packet(packet)
            if response and response.haslayer(ENIPHeader):
                if response.Status == ENIPStatus.SUCCESS.value:
                    self._session_handle = response.Session
                    self.logger.info(f"Session registered with handle: {self._session_handle}")
                    return True
                else:
                    self.logger.error(f"Session registration failed with status: {response.Status}")
                    return False
            else:
                self.logger.error("No response received for session registration")
                return False
                
        except Exception as e:
            self.logger.error(f"Error registering session: {e}")
            return False

    def _unregister_session(self) -> bool:
        """
        Unregister the current session
        
        Returns:
            bool: True if unregistration successful, False otherwise
        """
        try:
            if not self._session_handle:
                return True
                
            # Create unregister session packet
            packet = ENIPHeader(Command=ENIPCommand.UNREGISTER_SESSION.value, Session=self._session_handle)
            
            response = self.send_receive_packet(packet)
            if response and response.haslayer(ENIPHeader):
                if response.Status == ENIPStatus.SUCCESS.value:
                    self.logger.info("Session unregistered successfully")
                    return True
                else:
                    self.logger.warning(f"Session unregistration failed with status: {response.Status}")
                    return False
            else:
                self.logger.warning("No response received for session unregistration")
                return False
                
        except Exception as e:
            self.logger.error(f"Error unregistering session: {e}")
            return False

    def _check_session_validity(self) -> bool:
        """
        Check if the current session is still valid
        
        Returns:
            bool: True if session is valid, False otherwise
        """
        if not self._session_handle:
            return False
            
        # Check if session has expired
        if time.time() - self._session_start_time > self._session_timeout:
            self.logger.warning("Session has expired, reconnecting...")
            self.disconnect()
            return self.connect()
            
        return True

    def send_packet(self, packet: bytes) -> bool:
        """
        Send packet to ENIP device
        
        Args:
            packet: Packet data to send
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        if not self._connected or not self._connection:
            self.logger.error("Not connected to ENIP device")
            return False
            
        try:
            # Convert packet to bytes if it's a Scapy packet
            if hasattr(packet, 'build'):
                packet_data = packet.build()
            else:
                packet_data = packet
                
            self._connection.send(packet_data)
            return True
        except Exception as e:
            self.logger.error(f"Failed to send packet: {e}")
            return False

    def receive_packet(self, timeout: Optional[int] = None) -> Optional[bytes]:
        """
        Receive packet from ENIP device
        
        Args:
            timeout: Timeout for receiving (uses default if None)
            
        Returns:
            bytes: Received packet data or None if failed
        """
        if not self._connected or not self._connection:
            self.logger.error("Not connected to ENIP device")
            return None
            
        try:
            if timeout:
                self._connection.settimeout(timeout)
            else:
                self._connection.settimeout(self._timeout)
                
            data = self._connection.recv(4096)
            if data:
                return data
            else:
                self.logger.warning("No data received")
                return None
        except socket.timeout:
            self.logger.warning("Timeout receiving packet")
            return None
        except Exception as e:
            self.logger.error(f"Failed to receive packet: {e}")
            return None

    def send_receive_packet(self, packet: bytes, timeout: Optional[int] = None) -> Optional[bytes]:
        """
        Send packet and receive response
        
        Args:
            packet: Packet data to send
            timeout: Timeout for receiving (uses default if None)
            
        Returns:
            bytes: Response packet data or None if failed
        """
        if self.send_packet(packet):
            return self.receive_packet(timeout)
        return None

    def list_identity(self) -> Optional[Dict[str, Any]]:
        """
        Get device identity information
        
        Returns:
            Dict[str, Any]: Device identity information or None if failed
        """
        try:
            if not self._check_session_validity():
                return None
                
            # Create list identity packet
            packet = ENIPHeader(Command=ENIPCommand.LIST_IDENTITY.value, Session=self._session_handle)
            
            response = self.send_receive_packet(packet)
            if response and response.haslayer(ENIPHeader):
                if response.Status == ENIPStatus.SUCCESS.value and response.haslayer(ListIdentityResponse):
                    identity = response[ListIdentityResponse]
                    device_info = {
                        'product_name': identity.ProductName.decode('utf-8', errors='ignore') if identity.ProductName else '',
                        'device_type': identity.DeviceType,
                        'vendor_id': identity.VendorID,
                        'vendor_name': VENDOR_IDS.get(identity.VendorID, f"Unknown({identity.VendorID})"),
                        'revision': f"{identity.Revision >> 8}.{identity.Revision & 0xFF}",
                        'serial_number': f"{identity.SerialNumber:08X}",
                        'session_handle': self._session_handle
                    }
                    return device_info
                else:
                    self.logger.error(f"List identity failed with status: {response.Status}")
                    return None
            else:
                self.logger.error("No response received for list identity")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting device identity: {e}")
            return None

    def list_services(self) -> Optional[List[Dict[str, Any]]]:
        """
        Get list of services supported by the device
        
        Returns:
            List[Dict[str, Any]]: List of services or None if failed
        """
        try:
            if not self._check_session_validity():
                return None
                
            # Create list services packet
            packet = ENIPHeader(Command=ENIPCommand.LIST_SERVICES.value, Session=self._session_handle)
            
            response = self.send_receive_packet(packet)
            if response and response.haslayer(ENIPHeader):
                if response.Status == ENIPStatus.SUCCESS.value and response.haslayer(ListServiceResponse):
                    services = []
                    service_list = response[ListServiceResponse]
                    
                    # Parse services (simplified - actual parsing depends on response structure)
                    if hasattr(service_list, 'Services'):
                        for service in service_list.Services:
                            service_info = {
                                'service_type': service.ServiceType if hasattr(service, 'ServiceType') else 'Unknown',
                                'service_name': service.ServiceName.decode('utf-8', errors='ignore') if hasattr(service, 'ServiceName') else 'Unknown'
                            }
                            services.append(service_info)
                            
                    return services
                else:
                    self.logger.error(f"List services failed with status: {response.Status}")
                    return None
            else:
                self.logger.error("No response received for list services")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting services list: {e}")
            return None

    def send_rr_data(self, data: bytes, timeout: Optional[int] = None) -> Optional[bytes]:
        """
        Send Request/Response data to the device
        
        Args:
            data: Data to send
            timeout: Timeout for response (uses default if None)
            
        Returns:
            bytes: Response data or None if failed
        """
        try:
            if not self._check_session_validity():
                return None
                
            # Create send RR data packet
            packet = ENIPHeader(Command=ENIPCommand.SEND_RR_DATA.value, Session=self._session_handle) / \
                     CIPCommandSpecificData() / \
                     UnconnectedDataItem(Data=data)
            
            response = self.send_receive_packet(packet, timeout)
            if response and response.haslayer(ENIPHeader):
                if response.Status == ENIPStatus.SUCCESS.value:
                    # Extract response data
                    if response.haslayer(UnconnectedDataItem):
                        return response[UnconnectedDataItem].Data
                    return response
                else:
                    self.logger.error(f"Send RR data failed with status: {response.Status}")
                    return None
            else:
                self.logger.error("No response received for send RR data")
                return None
                
        except Exception as e:
            self.logger.error(f"Error sending RR data: {e}")
            return None

    def send_unit_data(self, data: bytes, timeout: Optional[int] = None) -> bool:
        """
        Send Unit data to the device
        
        Args:
            data: Data to send
            timeout: Timeout for response (uses default if None)
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            if not self._check_session_validity():
                return False
                
            # Create send unit data packet
            packet = ENIPHeader(Command=ENIPCommand.SEND_UNIT_DATA.value, Session=self._session_handle) / \
                     CIPCommandSpecificData() / \
                     ConnectedDataItem(Data=data)
            
            response = self.send_receive_packet(packet, timeout)
            if response and response.haslayer(ENIPHeader):
                if response.Status == ENIPStatus.SUCCESS.value:
                    self.logger.info("Unit data sent successfully")
                    return True
                else:
                    self.logger.error(f"Send unit data failed with status: {response.Status}")
                    return False
            else:
                self.logger.error("No response received for send unit data")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending unit data: {e}")
            return False

    def discover_devices(self, network_range: str = None) -> List[ENIPDevice]:
        """
        Discover ENIP devices on the network
        
        Args:
            network_range: Network range to scan (e.g., "192.168.1.0/24")
            
        Returns:
            List[ENIPDevice]: List of discovered devices
        """
        discovered_devices = []
        
        try:
            # This would typically use UDP broadcast/multicast for discovery
            # For now, we'll implement a simple TCP-based discovery
            if network_range:
                # Parse network range and scan each IP
                import ipaddress
                network = ipaddress.IPv4Network(network_range, strict=False)
                
                for ip in network.hosts():
                    try:
                        # Try to connect to each IP
                        temp_client = ENIPClient(f"temp_{ip}", str(ip), self._port, self._timeout)
                        if temp_client.connect():
                            identity = temp_client.list_identity()
                            if identity:
                                device = ENIPDevice(
                                    ip_address=str(ip),
                                    port=self._port,
                                    product_name=identity.get('product_name', ''),
                                    device_type=str(identity.get('device_type', '')),
                                    vendor_id=identity.get('vendor_id', 0),
                                    vendor_name=identity.get('vendor_name', ''),
                                    revision=identity.get('revision', ''),
                                    serial_number=identity.get('serial_number', ''),
                                    session_handle=identity.get('session_handle', 0)
                                )
                                discovered_devices.append(device)
                                self.logger.info(f"Discovered device at {ip}: {identity.get('product_name', 'Unknown')}")
                            
                            temp_client.disconnect()
                            
                    except Exception as e:
                        self.logger.debug(f"Failed to discover device at {ip}: {e}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error during device discovery: {e}")
            
        return discovered_devices

    def test_connection(self) -> bool:
        """
        Test connection to ENIP device
        
        Returns:
            bool: True if connection test successful, False otherwise
        """
        try:
            if not self._connected:
                if not self.connect():
                    return False
                    
            # Try to get device identity as a connection test
            identity = self.list_identity()
            if identity:
                self.logger.info("Connection test successful")
                return True
            else:
                self.logger.error("Connection test failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    def get_target_info(self) -> Tuple[str, str, str, str, str, str]:
        """
        Get target information
        
        Returns:
            Tuple[str, str, str, str, str, str]: Target information
        """
        try:
            identity = self.list_identity()
            if identity:
                target_info = (
                    f"ENIP Device at {self._target}:{self._port}",
                    f"Product: {identity.get('product_name', 'Unknown')}",
                    f"Vendor: {identity.get('vendor_name', 'Unknown')}",
                    f"Device Type: {identity.get('device_type', 'Unknown')}",
                    f"Revision: {identity.get('revision', 'Unknown')}",
                    f"Serial: {identity.get('serial_number', 'Unknown')}"
                )
            else:
                target_info = (
                    f"ENIP Device at {self._target}:{self._port}",
                    "Status: Connected" if self._connected else "Status: Disconnected",
                    "Session: " + str(self._session_handle) if self._session_handle else "Session: None",
                    "Unknown",
                    "Unknown",
                    "Unknown"
                )
                
            return target_info
            
        except Exception as e:
            self.logger.error(f"Error getting target info: {e}")
            return ("ENIP Device", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown")

    def check_permissions(self) -> Dict[str, bool]:
        """
        Check device permissions
        
        Returns:
            Dict[str, bool]: Permission status
        """
        permissions = {
            'readable': False,
            'writeable': False,
            'authorized': False
        }
        
        try:
            if self._connected:
                # Try to get device identity as a permission test
                identity = self.list_identity()
                if identity:
                    permissions['readable'] = True
                    
                # Try to send RR data as a permission test
                test_data = b'\x00\x00\x00\x00'  # Simple test data
                if self.send_rr_data(test_data):
                    permissions['writeable'] = True
                    
                permissions['authorized'] = permissions['readable'] or permissions['writeable']
                
        except Exception as e:
            self.logger.error(f"Error checking permissions: {e}")
            
        return permissions

    def __del__(self):
        """Cleanup on deletion"""
        self.disconnect()
