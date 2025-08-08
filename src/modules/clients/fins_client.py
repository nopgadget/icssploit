#!/usr/bin/env python3
"""
FINS Client for ICSSploit
A Python client to interact with Omron FINS devices
Based on the Wireshark dissector: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-omron-fins.c
and Redpoint NSE script: https://github.com/digitalbond/Redpoint/blob/master/omrontcp-info.nse
"""
import socket
import struct
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum
from dataclasses import dataclass
from src.modules.clients.base import Base


class FINSCommandCode(Enum):
    """FINS Command Codes"""
    # Memory Area Read/Write
    MEMORY_AREA_READ = 0x0101
    MEMORY_AREA_WRITE = 0x0102
    MEMORY_AREA_FILL = 0x0103
    MULTIPLE_MEMORY_AREA_READ = 0x0104
    MEMORY_AREA_TRANSFER = 0x0105
    
    # Parameter Area Read/Write
    PARAMETER_AREA_READ = 0x0201
    PARAMETER_AREA_WRITE = 0x0202
    PARAMETER_AREA_FILL = 0x0203
    
    # Program Area Read/Write
    PROGRAM_AREA_READ = 0x0301
    PROGRAM_AREA_WRITE = 0x0302
    PROGRAM_AREA_FILL = 0x0303
    
    # CPU Unit Data Read/Write
    CPU_UNIT_DATA_READ = 0x0401
    CPU_UNIT_DATA_WRITE = 0x0402
    
    # CPU Unit Status Read/Write
    CPU_UNIT_STATUS_READ = 0x0501
    CPU_UNIT_STATUS_WRITE = 0x0502
    
    # Run/Stop Control
    RUN = 0x0401
    STOP = 0x0402
    
    # Clock Read/Write
    CLOCK_READ = 0x0701
    CLOCK_WRITE = 0x0702
    
    # Message
    MESSAGE = 0x0801
    
    # Access Right Request/Release
    ACCESS_RIGHT_REQUEST = 0x0C01
    ACCESS_RIGHT_RELEASE = 0x0C02
    
    # Error Log Read/Clear
    ERROR_LOG_READ = 0x0D01
    ERROR_LOG_CLEAR = 0x0D02
    
    # FINS Node Address Read/Write
    FINS_NODE_ADDRESS_READ = 0x0E01
    FINS_NODE_ADDRESS_WRITE = 0x0E02
    
    # Network Status Read
    NETWORK_STATUS_READ = 0x0F01
    
    # Remote Node Status Read
    REMOTE_NODE_STATUS_READ = 0x0F02
    
    # Controller Data Read/Write
    CONTROLLER_DATA_READ = 0x1001
    CONTROLLER_DATA_WRITE = 0x1002
    
    # Connection Data Read/Write
    CONNECTION_DATA_READ = 0x1101
    CONNECTION_DATA_WRITE = 0x1102


class FINSMemoryArea(Enum):
    """FINS Memory Areas"""
    CIO = 0xB0  # CIO (Common I/O)
    WR = 0xB1   # Work Area
    HR = 0xB2   # Holding Area
    AR = 0xB3   # Auxiliary Area
    DM = 0x82   # Data Memory
    EM = 0xA0   # Extended Data Memory
    TIM = 0x89  # Timer Area
    CNT = 0x89  # Counter Area
    TASK = 0x04 # Task Area


class FINSResponseCode(Enum):
    """FINS Response Codes"""
    NORMAL_COMPLETION = 0x0000
    LOCAL_NODE_NOT_IN_NETWORK = 0x0001
    DESTINATION_NODE_NOT_IN_NETWORK = 0x0002
    COMMUNICATIONS_UNIT_ERROR = 0x0003
    DESTINATION_NODE_DUPLICATE_FINS_ADDRESS = 0x0004
    TOO_MANY_SEND_FRAMES = 0x0005
    NODE_NUMBER_RANGE_ERROR = 0x0006
    DESTINATION_NODE_FINS_MESSAGE_OVERFLOW = 0x0007
    FORMAT_ERROR = 0x0008
    NOT_RECEIVABLE = 0x0009
    DESTINATION_NODE_WATCHDOG_TIMER_ERROR = 0x000A
    DESTINATION_NODE_FINS_BUFFER_OVERFLOW = 0x000B
    DESTINATION_NODE_FINS_BUFFER_FULL = 0x000C
    DESTINATION_NODE_FINS_MESSAGE_LENGTH_ERROR = 0x000D
    DESTINATION_NODE_FINS_COMMAND_FORMAT_ERROR = 0x000E
    DESTINATION_NODE_FINS_COMMAND_NOT_SUPPORTED = 0x000F
    DESTINATION_NODE_FINS_COMMAND_PROCESSING_ERROR = 0x0010
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR = 0x0011
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_TIMEOUT = 0x0012
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ABORTED = 0x0013
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_DISABLED = 0x0014
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_NOT_READY = 0x0015
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_BUSY = 0x0016
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_2 = 0x0017
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_3 = 0x0018
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_4 = 0x0019
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_5 = 0x001A
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_6 = 0x001B
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_7 = 0x001C
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_8 = 0x001D
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_9 = 0x001E
    DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR_10 = 0x001F


@dataclass
class FINSDevice:
    """FINS Device Information"""
    node_address: int
    ip_address: str
    device_name: str = ""
    vendor_name: str = ""
    model_name: str = ""
    version: str = ""
    serial_number: str = ""


class FINSClient(Base):
    """FINS Client for ICSSploit"""
    
    options = ['target', 'port', 'node_address', 'timeout', 'retry_count']
    
    def __init__(self, name: str, target: str = '', port: int = 9600,
                 node_address: int = 0, timeout: int = 2, retry_count: int = 3):
        super(FINSClient, self).__init__(name=name)
        self._target = target
        self._port = port
        self._node_address = node_address
        self._timeout = timeout
        self._retry_count = retry_count
        self._connection = None
        self._connected = False
        self._sequence_number = 0
        self._client_node_address = 0
        self._server_node_address = 0
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
    def node_address(self):
        """Get node address"""
        return self._node_address
    
    @node_address.setter
    def node_address(self, value):
        """Set node address"""
        self._node_address = int(value)
    
    @property
    def timeout(self):
        """Get timeout"""
        return self._timeout
    
    @timeout.setter
    def timeout(self, value):
        """Set timeout"""
        self._timeout = int(value)
    
    @property
    def retry_count(self):
        """Get retry count"""
        return self._retry_count
    
    @retry_count.setter
    def retry_count(self, value):
        """Set retry count"""
        self._retry_count = int(value)
    
    def connect(self) -> bool:
        """
        Connect to FINS device
        
        :return: True if connection successful, False otherwise
        """
        try:
            if self._connected:
                self.logger.warning("Already connected to FINS device")
                return True
            
            self.logger.info(f"Connecting to FINS device at {self._target}:{self._port}")
            
            # Create socket connection
            self._connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._connection.settimeout(self._timeout)
            self._connection.connect((self._target, self._port))
            
            # Send FINS handshake
            if self._send_fins_handshake():
                self._connected = True
                self.logger.info("Successfully connected to FINS device")
                return True
            else:
                self.logger.error("Failed to establish FINS handshake")
                self.disconnect()
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to connect to FINS device: {e}")
            self.disconnect()
            return False
    
    def disconnect(self):
        """Disconnect from FINS device"""
        try:
            if self._connection:
                self._connection.close()
                self._connection = None
            self._connected = False
            self.logger.info("Disconnected from FINS device")
        except Exception as e:
            self.logger.error(f"Error during disconnect: {e}")
    
    def _send_fins_handshake(self) -> bool:
        """
        Send FINS handshake to establish connection
        
        :return: True if handshake successful, False otherwise
        """
        try:
            # FINS handshake packet structure
            # Command: 0x46494E53 (FINS)
            # Error Code: 0x00000000
            # Client Node Address: 0x00000000
            # Server Node Address: 0x00000000
            
            handshake = struct.pack('>4s4s4s4s', 
                                  b'FINS',           # Command
                                  b'\x00\x00\x00\x00',  # Error Code
                                  b'\x00\x00\x00\x00',  # Client Node Address
                                  b'\x00\x00\x00\x00')  # Server Node Address
            
            self.logger.debug(f"Sending FINS handshake: {handshake.hex()}")
            
            # Send handshake
            self._connection.send(handshake)
            
            # Receive response
            response = self._connection.recv(16)
            if len(response) >= 16:
                cmd, error_code, client_addr, server_addr = struct.unpack('>4s4s4s4s', response)
                
                if cmd == b'FINS' and error_code == b'\x00\x00\x00\x00':
                    self._client_node_address = struct.unpack('>I', client_addr)[0]
                    self._server_node_address = struct.unpack('>I', server_addr)[0]
                    self.logger.info(f"FINS handshake successful - Client: {self._client_node_address}, Server: {self._server_node_address}")
                    return True
                else:
                    self.logger.error(f"FINS handshake failed - Error code: {error_code.hex()}")
                    return False
            else:
                self.logger.error("Invalid FINS handshake response")
                return False
                
        except Exception as e:
            self.logger.error(f"Error during FINS handshake: {e}")
            return False
    
    def _create_fins_header(self, command_code: FINSCommandCode, data_length: int = 0) -> bytes:
        """
        Create FINS packet header
        
        :param command_code: FINS command code
        :param data_length: Length of data field
        :return: FINS header bytes
        """
        # FINS header structure:
        # ICF (Information Control Field): 1 byte
        # RSV (Reserved): 1 byte
        # GCT (Gateway Count): 1 byte
        # DNA (Destination Network Address): 1 byte
        # DA1 (Destination Node Address): 1 byte
        # DA2 (Destination Unit Address): 1 byte
        # SNA (Source Network Address): 1 byte
        # SA1 (Source Node Address): 1 byte
        # SA2 (Source Unit Address): 1 byte
        # SID (Service ID): 1 byte
        # Command Code: 2 bytes
        # Error Code: 2 bytes
        
        icf = 0x80  # Information Control Field (Response required)
        rsv = 0x00  # Reserved
        gct = 0x02  # Gateway Count
        dna = 0x00  # Destination Network Address
        da1 = self._server_node_address  # Destination Node Address
        da2 = 0x00  # Destination Unit Address
        sna = 0x00  # Source Network Address
        sa1 = self._client_node_address  # Source Node Address
        sa2 = 0x00  # Source Unit Address
        sid = self._sequence_number  # Service ID
        
        header = struct.pack('>BBBBBBBBBBHH',
                           icf, rsv, gct, dna, da1, da2, sna, sa1, sa2, sid,
                           command_code.value, 0x0000)  # Command Code, Error Code
        
        return header
    
    def _increment_sequence(self):
        """Increment sequence number"""
        self._sequence_number = (self._sequence_number + 1) % 256
    
    def send_packet(self, packet: bytes) -> bool:
        """
        Send packet to FINS device
        
        :param packet: Packet to send
        :return: True if sent successfully, False otherwise
        """
        try:
            if not self._connected:
                self.logger.error("Not connected to FINS device")
                return False
            
            self.logger.debug(f"Sending packet: {packet.hex()}")
            self._connection.send(packet)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send packet: {e}")
            return False
    
    def receive_packet(self, timeout: Optional[int] = None) -> Optional[bytes]:
        """
        Receive packet from FINS device
        
        :param timeout: Timeout in seconds
        :return: Received packet or None if failed
        """
        try:
            if not self._connected:
                self.logger.error("Not connected to FINS device")
                return None
            
            if timeout:
                self._connection.settimeout(timeout)
            
            packet = self._connection.recv(4096)
            if packet:
                self.logger.debug(f"Received packet: {packet.hex()}")
                return packet
            else:
                self.logger.warning("No data received")
                return None
                
        except socket.timeout:
            self.logger.warning("Timeout waiting for response")
            return None
        except Exception as e:
            self.logger.error(f"Failed to receive packet: {e}")
            return None
    
    def send_receive_packet(self, packet: bytes, timeout: Optional[int] = None) -> Optional[bytes]:
        """
        Send packet and receive response
        
        :param packet: Packet to send
        :param timeout: Timeout in seconds
        :return: Response packet or None if failed
        """
        if self.send_packet(packet):
            return self.receive_packet(timeout)
        return None
    
    def read_memory_area(self, memory_area: FINSMemoryArea, start_address: int, 
                        count: int = 1) -> Optional[List[int]]:
        """
        Read from memory area
        
        :param memory_area: Memory area to read from
        :param start_address: Starting address
        :param count: Number of items to read
        :return: List of read values or None if failed
        """
        try:
            command_code = FINSCommandCode.MEMORY_AREA_READ
            
            # Create memory area read command
            data = struct.pack('>BHHH',
                             memory_area.value,  # Memory area code
                             start_address,      # Starting address
                             count,              # Item count
                             0x0000)             # Reserved
            
            header = self._create_fins_header(command_code, len(data))
            packet = header + data
            
            self._increment_sequence()
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 16:
                # Parse response
                if len(response) > 16:
                    data_section = response[16:]
                    # Parse the data based on memory area type
                    values = []
                    for i in range(0, len(data_section), 2):
                        if i + 1 < len(data_section):
                            value = struct.unpack('>H', data_section[i:i+2])[0]
                            values.append(value)
                    return values
                else:
                    self.logger.warning("No data in response")
                    return []
            else:
                self.logger.error("Failed to read memory area")
                return None
                
        except Exception as e:
            self.logger.error(f"Error reading memory area: {e}")
            return None
    
    def write_memory_area(self, memory_area: FINSMemoryArea, start_address: int, 
                         values: List[int]) -> bool:
        """
        Write to memory area
        
        :param memory_area: Memory area to write to
        :param start_address: Starting address
        :param values: Values to write
        :return: True if successful, False otherwise
        """
        try:
            command_code = FINSCommandCode.MEMORY_AREA_WRITE
            
            # Create data section
            data = struct.pack('>BHH', memory_area.value, start_address, len(values))
            for value in values:
                data += struct.pack('>H', value)
            
            header = self._create_fins_header(command_code, len(data))
            packet = header + data
            
            self._increment_sequence()
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 16:
                # Check for error code
                error_code = struct.unpack('>H', response[14:16])[0]
                if error_code == 0x0000:
                    self.logger.info(f"Successfully wrote {len(values)} values to memory area")
                    return True
                else:
                    self.logger.error(f"Write failed with error code: {error_code:04X}")
                    return False
            else:
                self.logger.error("Failed to write memory area")
                return False
                
        except Exception as e:
            self.logger.error(f"Error writing memory area: {e}")
            return False
    
    def get_cpu_unit_status(self) -> Optional[Dict[str, Any]]:
        """
        Get CPU unit status
        
        :return: CPU status information or None if failed
        """
        try:
            command_code = FINSCommandCode.CPU_UNIT_STATUS_READ
            
            header = self._create_fins_header(command_code)
            packet = header
            
            self._increment_sequence()
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 16:
                if len(response) > 16:
                    status_data = response[16:]
                    # Parse status data (structure depends on CPU model)
                    status = {
                        'run_mode': status_data[0] if len(status_data) > 0 else 0,
                        'cpu_unit_status': status_data[1] if len(status_data) > 1 else 0,
                        'error_code': status_data[2:4] if len(status_data) > 3 else b'\x00\x00'
                    }
                    return status
                else:
                    self.logger.warning("No status data in response")
                    return {}
            else:
                self.logger.error("Failed to get CPU unit status")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting CPU unit status: {e}")
            return None
    
    def run_cpu(self) -> bool:
        """
        Start CPU execution
        
        :return: True if successful, False otherwise
        """
        try:
            command_code = FINSCommandCode.RUN
            
            header = self._create_fins_header(command_code)
            packet = header
            
            self._increment_sequence()
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 16:
                error_code = struct.unpack('>H', response[14:16])[0]
                if error_code == 0x0000:
                    self.logger.info("CPU started successfully")
                    return True
                else:
                    self.logger.error(f"Failed to start CPU - Error code: {error_code:04X}")
                    return False
            else:
                self.logger.error("Failed to start CPU")
                return False
                
        except Exception as e:
            self.logger.error(f"Error starting CPU: {e}")
            return False
    
    def stop_cpu(self) -> bool:
        """
        Stop CPU execution
        
        :return: True if successful, False otherwise
        """
        try:
            command_code = FINSCommandCode.STOP
            
            header = self._create_fins_header(command_code)
            packet = header
            
            self._increment_sequence()
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 16:
                error_code = struct.unpack('>H', response[14:16])[0]
                if error_code == 0x0000:
                    self.logger.info("CPU stopped successfully")
                    return True
                else:
                    self.logger.error(f"Failed to stop CPU - Error code: {error_code:04X}")
                    return False
            else:
                self.logger.error("Failed to stop CPU")
                return False
                
        except Exception as e:
            self.logger.error(f"Error stopping CPU: {e}")
            return False
    
    def get_clock(self) -> Optional[Dict[str, int]]:
        """
        Get device clock
        
        :return: Clock information or None if failed
        """
        try:
            command_code = FINSCommandCode.CLOCK_READ
            
            header = self._create_fins_header(command_code)
            packet = header
            
            self._increment_sequence()
            
            response = self.send_receive_packet(packet)
            if response and len(response) >= 16:
                if len(response) >= 24:
                    clock_data = response[16:24]
                    year, month, day, hour, minute, second, day_of_week = struct.unpack('>BBBBBBB', clock_data)
                    return {
                        'year': year + 2000,
                        'month': month,
                        'day': day,
                        'hour': hour,
                        'minute': minute,
                        'second': second,
                        'day_of_week': day_of_week
                    }
                else:
                    self.logger.warning("Invalid clock data in response")
                    return None
            else:
                self.logger.error("Failed to get clock")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting clock: {e}")
            return None
    
    def discover_devices(self, network_range: str = None) -> List[FINSDevice]:
        """
        Discover FINS devices on the network
        
        :param network_range: Network range to scan (e.g., "192.168.1.0/24")
        :return: List of discovered devices
        """
        devices = []
        
        try:
            if network_range:
                import ipaddress
                network = ipaddress.IPv4Network(network_range, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            else:
                # Default to common FINS ports and local network
                targets = [self._target] if self._target else []
            
            for target in targets:
                try:
                    # Try to connect to each target
                    temp_client = FINSClient(f"discovery_{target}", target, self._port)
                    if temp_client.connect():
                        device = FINSDevice(
                            node_address=temp_client._server_node_address,
                            ip_address=target
                        )
                        devices.append(device)
                        temp_client.disconnect()
                except Exception as e:
                    self.logger.debug(f"Failed to discover device at {target}: {e}")
                    continue
            
            self.logger.info(f"Discovered {len(devices)} FINS devices")
            return devices
            
        except Exception as e:
            self.logger.error(f"Error during device discovery: {e}")
            return devices
    
    def test_connection(self) -> bool:
        """
        Test connection to FINS device
        
        :return: True if connection test successful, False otherwise
        """
        try:
            if not self._connected:
                return False
            
            # Try to read a small amount of data to test connection
            status = self.get_cpu_unit_status()
            return status is not None
            
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def get_target_info(self) -> Tuple[str, str, str, str, str, str]:
        """
        Get target information
        
        :return: Tuple of (target, port, node_address, status, version, description)
        """
        status = "Connected" if self._connected else "Disconnected"
        version = "FINS Protocol"
        description = f"Omron FINS Device - Node {self._server_node_address}"
        
        return (self._target, str(self._port), str(self._node_address), 
                status, version, description)
    
    def check_permissions(self) -> Dict[str, bool]:
        """
        Check device permissions
        
        :return: Dictionary of permission checks
        """
        permissions = {
            'read_memory': False,
            'write_memory': False,
            'control_cpu': False,
            'read_status': False
        }
        
        try:
            if not self._connected:
                return permissions
            
            # Test read memory permission
            test_read = self.read_memory_area(FINSMemoryArea.DM, 0, 1)
            permissions['read_memory'] = test_read is not None
            
            # Test read status permission
            test_status = self.get_cpu_unit_status()
            permissions['read_status'] = test_status is not None
            
            # Test control CPU permission (read-only test)
            permissions['control_cpu'] = True  # Assume control permission if connected
            
            # Test write memory permission (read-only test for safety)
            permissions['write_memory'] = True  # Assume write permission if connected
            
        except Exception as e:
            self.logger.error(f"Error checking permissions: {e}")
        
        return permissions
    
    def __del__(self):
        """Cleanup on deletion"""
        self.disconnect()
