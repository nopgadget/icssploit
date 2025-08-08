#!/usr/bin/env python3
"""
CC-Link Client for ICSSploit
A Python client to interact with CC-Link IE Field Basic devices
Based on the Zeek parser: https://github.com/nttcom/zeek-parser-CCLinkFieldBasic/
"""

import socket
import struct
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum
from dataclasses import dataclass
from src.modules.clients.base import Base


class CCLinkFunctionCode(Enum):
    """CC-Link IE Field Basic function codes"""
    CYCLIC_DATA_REQ = 0x01
    CYCLIC_DATA_RES = 0x02
    TRANSIENT_REQ = 0x03
    TRANSIENT_RES = 0x04
    MASTER_STATION_PARAMETER_SETTING_REQ = 0x05
    MASTER_STATION_PARAMETER_SETTING_RES = 0x06
    SLAVE_STATION_PARAMETER_SETTING_REQ = 0x07
    SLAVE_STATION_PARAMETER_SETTING_RES = 0x08
    NETWORK_STATUS_REQ = 0x09
    NETWORK_STATUS_RES = 0x0A
    STATION_STATUS_REQ = 0x0B
    STATION_STATUS_RES = 0x0C
    ERROR_STATUS_REQ = 0x0D
    ERROR_STATUS_RES = 0x0E


class CCLinkStationType(Enum):
    """CC-Link station types"""
    MASTER = 0x00
    SLAVE = 0x01
    INTELLIGENT = 0x02


class CCLinkErrorCode(Enum):
    """CC-Link error codes"""
    NO_ERROR = 0x00
    COMMUNICATION_ERROR = 0x01
    PARAMETER_ERROR = 0x02
    STATION_ERROR = 0x03
    TIMEOUT_ERROR = 0x04


@dataclass
class CCLinkDevice:
    """Represents a CC-Link device"""
    station_number: int
    station_type: CCLinkStationType
    ip_address: str
    port: int = 61450
    device_name: str = ""
    model_name: str = ""
    manufacturer: str = ""


class CCLinkClient(Base):
    """CC-Link IE Field Basic client for ICSSploit"""
    
    # Client options (similar to module options)
    options = ['target', 'port', 'station_number', 'station_type', 'timeout', 'retry_count']
    
    def __init__(self, name: str, target: str = '', port: int = 61450, 
                 station_number: int = 1, station_type: CCLinkStationType = CCLinkStationType.MASTER,
                 timeout: int = 2, retry_count: int = 3):
        """
        Initialize CC-Link client
        
        Args:
            name: Name of this target
            target: Target CC-Link device IP
            port: CC-Link port (default: 61450)
            station_number: Station number (default: 1)
            station_type: Station type - MASTER, SLAVE, or INTELLIGENT (default: MASTER)
            timeout: Socket timeout (default: 2)
            retry_count: Number of retries for failed operations (default: 3)
        """
        super(CCLinkClient, self).__init__(name=name)
        self._target = target
        self._port = port
        self._station_number = station_number
        self._station_type = station_type
        self._timeout = timeout
        self._retry_count = retry_count
        self._connection = None
        self._connected = False
        self._sequence_number = 0
        self._session_id = None
        
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
    def station_number(self):
        """Get station number"""
        return self._station_number
        
    @station_number.setter
    def station_number(self, value):
        """Set station number"""
        if value == '' or value is None:
            raise ValueError("Station number cannot be empty")
        self._station_number = int(value)
        
    @property
    def station_type(self):
        """Get station type"""
        return self._station_type
        
    @station_type.setter
    def station_type(self, value):
        """Set station type"""
        if isinstance(value, str):
            value = CCLinkStationType[value.upper()]
        self._station_type = value
        
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
        Connect to the CC-Link device
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            if self._connected and self._connection:
                self.logger.info("Already connected")
                return True
                
            self.logger.info(f"Connecting to CC-Link device at {self._target}:{self._port}")
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((self._target, self._port))
            self._connection = sock
            self._connected = True
            
            # Initialize session
            self._sequence_number = 0
            self._session_id = int(time.time())
            
            self.logger.info(f"Successfully connected to CC-Link device at {self._target}:{self._port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to CC-Link device: {e}")
            self._connected = False
            return False

    def disconnect(self):
        """Disconnect from the CC-Link device"""
        try:
            if self._connection:
                self._connection.close()
                self._connection = None
                self._connected = False
                self.logger.info("Disconnected from CC-Link device")
        except Exception as e:
            self.logger.error(f"Error disconnecting: {e}")

    def _create_header(self, function_code: CCLinkFunctionCode, data_length: int = 0) -> bytes:
        """
        Create CC-Link packet header
        
        Args:
            function_code: Function code for the packet
            data_length: Length of data payload
            
        Returns:
            bytes: Packet header
        """
        header = struct.pack('>BBHHH',
            0x46,  # CC-Link protocol identifier
            function_code.value,
            self._station_number,
            self._sequence_number,
            data_length
        )
        return header

    def _increment_sequence(self):
        """Increment sequence number"""
        self._sequence_number = (self._sequence_number + 1) % 65536

    def send_packet(self, packet: bytes) -> bool:
        """
        Send packet to CC-Link device
        
        Args:
            packet: Packet data to send
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        if not self._connected or not self._connection:
            self.logger.error("Not connected to CC-Link device")
            return False
            
        try:
            self._connection.send(packet)
            self._increment_sequence()
            return True
        except Exception as e:
            self.logger.error(f"Failed to send packet: {e}")
            return False

    def receive_packet(self, timeout: Optional[int] = None) -> Optional[bytes]:
        """
        Receive packet from CC-Link device
        
        Args:
            timeout: Timeout for receiving (uses default if None)
            
        Returns:
            bytes: Received packet data or None if failed
        """
        if not self._connected or not self._connection:
            self.logger.error("Not connected to CC-Link device")
            return None
            
        try:
            if timeout:
                self._connection.settimeout(timeout)
            else:
                self._connection.settimeout(self._timeout)
                
            data = self._connection.recv(1024)
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

    def read_cyclic_data(self, start_address: int = 0, count: int = 1) -> Optional[List[int]]:
        """
        Read cyclic data from CC-Link device
        
        Args:
            start_address: Starting address to read from
            count: Number of words to read
            
        Returns:
            List[int]: List of read values or None if failed
        """
        try:
            # Create cyclic data request packet
            data = struct.pack('>HH', start_address, count)
            header = self._create_header(CCLinkFunctionCode.CYCLIC_DATA_REQ, len(data))
            packet = header + data
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 8:
                # Parse response (simplified - actual parsing would depend on protocol spec)
                data_length = struct.unpack('>H', response[6:8])[0]
                if len(response) >= 8 + data_length:
                    data_bytes = response[8:8+data_length]
                    # Convert to list of integers (assuming 16-bit words)
                    values = []
                    for i in range(0, len(data_bytes), 2):
                        if i + 1 < len(data_bytes):
                            value = struct.unpack('>H', data_bytes[i:i+2])[0]
                            values.append(value)
                    return values
                    
            self.logger.error("Failed to read cyclic data")
            return None
            
        except Exception as e:
            self.logger.error(f"Error reading cyclic data: {e}")
            return None

    def write_cyclic_data(self, start_address: int, values: List[int]) -> bool:
        """
        Write cyclic data to CC-Link device
        
        Args:
            start_address: Starting address to write to
            values: List of values to write
            
        Returns:
            bool: True if write successful, False otherwise
        """
        try:
            # Create cyclic data write packet
            data = struct.pack('>HH', start_address, len(values))
            for value in values:
                data += struct.pack('>H', value)
                
            header = self._create_header(CCLinkFunctionCode.CYCLIC_DATA_REQ, len(data))
            packet = header + data
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 8:
                # Check for success response
                function_code = response[1]
                if function_code == CCLinkFunctionCode.CYCLIC_DATA_RES.value:
                    self.logger.info(f"Successfully wrote {len(values)} values to address {start_address}")
                    return True
                    
            self.logger.error("Failed to write cyclic data")
            return False
            
        except Exception as e:
            self.logger.error(f"Error writing cyclic data: {e}")
            return False

    def get_station_status(self) -> Optional[Dict[str, Any]]:
        """
        Get station status from CC-Link device
        
        Returns:
            Dict[str, Any]: Station status information or None if failed
        """
        try:
            # Create station status request packet
            header = self._create_header(CCLinkFunctionCode.STATION_STATUS_REQ, 0)
            packet = header
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 8:
                # Parse station status response (simplified)
                status_info = {
                    'station_number': struct.unpack('>H', response[2:4])[0],
                    'station_type': response[4] if len(response) > 4 else 0,
                    'status': response[5] if len(response) > 5 else 0,
                    'error_code': response[6] if len(response) > 6 else 0
                }
                return status_info
                
            self.logger.error("Failed to get station status")
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting station status: {e}")
            return None

    def get_network_status(self) -> Optional[Dict[str, Any]]:
        """
        Get network status from CC-Link device
        
        Returns:
            Dict[str, Any]: Network status information or None if failed
        """
        try:
            # Create network status request packet
            header = self._create_header(CCLinkFunctionCode.NETWORK_STATUS_REQ, 0)
            packet = header
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 8:
                # Parse network status response (simplified)
                network_info = {
                    'total_stations': struct.unpack('>H', response[2:4])[0] if len(response) >= 4 else 0,
                    'active_stations': response[4] if len(response) > 4 else 0,
                    'network_status': response[5] if len(response) > 5 else 0
                }
                return network_info
                
            self.logger.error("Failed to get network status")
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting network status: {e}")
            return None

    def discover_devices(self, start_station: int = 1, end_station: int = 64) -> List[CCLinkDevice]:
        """
        Discover CC-Link devices on the network
        
        Args:
            start_station: Starting station number for discovery
            end_station: Ending station number for discovery
            
        Returns:
            List[CCLinkDevice]: List of discovered devices
        """
        discovered_devices = []
        
        for station_num in range(start_station, end_station + 1):
            try:
                # Temporarily change station number for discovery
                original_station = self._station_number
                self._station_number = station_num
                
                # Try to get station status
                status = self.get_station_status()
                if status:
                    device = CCLinkDevice(
                        station_number=station_num,
                        station_type=CCLinkStationType(status.get('station_type', 0)),
                        ip_address=self._target,
                        port=self._port
                    )
                    discovered_devices.append(device)
                    self.logger.info(f"Discovered device at station {station_num}")
                    
                # Restore original station number
                self._station_number = original_station
                
            except Exception as e:
                self.logger.debug(f"Station {station_num} not responding: {e}")
                continue
                
        return discovered_devices

    def test_connection(self) -> bool:
        """
        Test connection to CC-Link device
        
        Returns:
            bool: True if connection test successful, False otherwise
        """
        try:
            if not self._connected:
                if not self.connect():
                    return False
                    
            # Try to get station status as a connection test
            status = self.get_station_status()
            if status:
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
            status = self.get_station_status()
            network_status = self.get_network_status()
            
            target_info = (
                f"CC-Link Device at {self._target}:{self._port}",
                f"Station {self._station_number} ({self._station_type.name})",
                f"Status: {'Connected' if self._connected else 'Disconnected'}",
                f"Network Status: {network_status.get('network_status', 'Unknown') if network_status else 'Unknown'}",
                f"Active Stations: {network_status.get('active_stations', 'Unknown') if network_status else 'Unknown'}",
                f"Total Stations: {network_status.get('total_stations', 'Unknown') if network_status else 'Unknown'}"
            )
            
            return target_info
            
        except Exception as e:
            self.logger.error(f"Error getting target info: {e}")
            return ("CC-Link Device", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown")

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
                # Try to read cyclic data as a permission test
                test_data = self.read_cyclic_data(0, 1)
                if test_data is not None:
                    permissions['readable'] = True
                    
                # Try to write cyclic data as a permission test
                if self.write_cyclic_data(0, [0]):
                    permissions['writeable'] = True
                    
                permissions['authorized'] = permissions['readable'] or permissions['writeable']
                
        except Exception as e:
            self.logger.error(f"Error checking permissions: {e}")
            
        return permissions

    def __del__(self):
        """Cleanup on deletion"""
        self.disconnect()
