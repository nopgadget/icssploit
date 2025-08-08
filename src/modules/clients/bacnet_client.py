#!/usr/bin/env python3
"""
BACnet Client for ICSSploit
A Python client to interact with BACnet devices
"""

import asyncio
import socket
import struct
import time
import sys
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from src.modules.clients.base import Base


class BACnetObjectType(Enum):
    """BACnet object types"""
    DEVICE = 8
    ANALOG_INPUT = 0
    ANALOG_OUTPUT = 1
    ANALOG_VALUE = 2
    BINARY_INPUT = 3
    BINARY_OUTPUT = 4
    BINARY_VALUE = 5
    MULTI_STATE_INPUT = 13
    MULTI_STATE_OUTPUT = 14
    MULTI_STATE_VALUE = 19


class BACnetProperty(Enum):
    """BACnet property identifiers"""
    OBJECT_NAME = 77
    PRESENT_VALUE = 85
    DESCRIPTION = 28
    UNITS = 117
    STATUS_FLAGS = 111
    RELIABILITY = 103
    OUT_OF_SERVICE = 81
    VENDOR_NAME = 96
    VENDOR_IDENTIFIER = 97
    MODEL_NAME = 70
    FIRMWARE_REVISION = 44
    APPLICATION_SOFTWARE_VERSION = 12
    LOCATION = 58
    PROTOCOL_VERSION = 98
    PROTOCOL_REVISION = 99
    SYSTEM_STATUS = 112
    MAX_APDU_LENGTH_ACCEPTED = 62
    SEGMENTATION_SUPPORTED = 107
    PRIORITY_ARRAY = 87
    RELINQUISH_DEFAULT = 95
    MINIMUM_ON_TIME = 81
    MINIMUM_OFF_TIME = 82
    ALARM_VALUE = 5
    COV_INCREMENT = 125
    TIME_DELAY = 113
    NOTIFICATION_CLASS = 17
    EVENT_ENABLE = 35
    ACKED_TRANSITIONS = 0
    NOTIFICATION_TYPE = 237
    EVENT_TIME_STAMPS = 130
    EVENT_MESSAGE_TEXTS = 131
    EVENT_MESSAGE_TEXTS_FORMAT = 132
    EVENT_STATE = 36
    EVENT_TYPE = 37
    EVENT_PARAMETERS = 83
    EVENT_TIME = 40
    ACKNOWLEDGE_TRANSITIONS = 0
    ACKNOWLEDGE_ALARMS = 1
    CONFIRMED_COV_NOTIFICATIONS = 2
    CONFIRMED_EVENT_NOTIFICATIONS = 3
    GET_ALARM_SUMMARY = 4
    GET_ENROLLMENT_SUMMARY = 5
    GET_EVENT_INFORMATION = 29
    SUBSCRIBE_COV = 5
    SUBSCRIBE_COV_PROPERTY = 28
    LIFE_SAFETY_OPERATION = 20
    PRIVATE_TRANSFER = 4
    TEXT_MESSAGE = 6
    REINITIALIZE_DEVICE = 19
    VIRTUAL_TERMINAL = 18
    AUTHENTICATE = 22
    REQUEST_KEY = 25
    I_AM = 26
    I_HAVE = 27
    WHO_IS = 28
    WHO_HAS = 29
    READ_PROPERTY = 12
    READ_PROPERTY_CONDITIONAL = 13
    READ_PROPERTY_MULTIPLE = 14
    READ_RANGE = 26
    READ_TAG = 27
    WRITE_PROPERTY = 15
    WRITE_PROPERTY_MULTIPLE = 16
    WRITE_GROUP = 17
    DELETE_OBJECT = 11
    CREATE_OBJECT = 10
    ADD_LIST_ELEMENT = 8
    REMOVE_LIST_ELEMENT = 9


@dataclass
class BACnetDevice:
    """Represents a discovered BACnet device"""
    device_id: int
    address: str
    vendor_id: Optional[int] = None
    vendor_name: Optional[str] = None
    model_name: Optional[str] = None


class BACnetAPDU:
    """BACnet APDU (Application Protocol Data Unit) handling"""
    
    @staticmethod
    def create_who_is_request(low_limit: int = 0, high_limit: int = 4194303) -> bytes:
        """Create a Who-Is request"""
        # BACnet APDU header
        apdu_type = 0x08  # Unconfirmed-Request
        service_choice = 0x10  # Who-Is
        
        # Create APDU
        apdu = struct.pack('!BB', apdu_type, service_choice)
        
        # Add limits if specified
        if low_limit != 0 or high_limit != 4194303:
            apdu += struct.pack('!BIII', 0x0B, low_limit, 0x0C, high_limit)
        
        return apdu
    
    @staticmethod
    def create_read_property_request(object_id: int, object_type: int, 
                                   property_id: int, array_index: Optional[int] = None) -> bytes:
        """Create a Read-Property request"""
        # BACnet APDU header - use proper confirmed request format
        apdu_type = 0x00  # Confirmed-Request
        service_choice = 0x0C  # ReadProperty
        
        # Create APDU with proper BACnet encoding
        # All confirmed requests need an invoke ID
        apdu = struct.pack('!BBB', apdu_type, service_choice, 0x01)  # Invoke ID
        
        # Object identifier (device,1) - use context tag 0 for ReadProperty
        apdu += struct.pack('!B', 0x00)  # Context tag 0 for object identifier
        apdu += struct.pack('!B', 0x04)  # Length (4 bytes)
        apdu += struct.pack('!HH', object_type, object_id)  # Object type and instance
        
        # Property identifier - use context tag 1 for ReadProperty
        apdu += struct.pack('!B', 0x01)  # Context tag 1 for property identifier
        apdu += struct.pack('!B', 0x02)  # Length (2 bytes)
        apdu += struct.pack('!H', property_id)  # Property identifier value
        
        # Array index (optional)
        if array_index is not None:
            apdu += struct.pack('!B', 0x12)  # Array index tag
            apdu += struct.pack('!B', 0x02)  # Array index length (2 bytes)
            apdu += struct.pack('!H', array_index)  # Array index value
        
        return apdu
    
    @staticmethod
    def create_write_property_request(object_id: int, object_type: int,
                                   property_id: int, value: Any,
                                   array_index: Optional[int] = None) -> bytes:
        """Create a Write-Property request"""
        # BACnet APDU header
        apdu_type = 0x00  # Confirmed-Request
        service_choice = 0x0F  # WriteProperty
        
        # Create APDU
        apdu = struct.pack('!BB', apdu_type, service_choice)
        
        # Object identifier
        apdu += struct.pack('!BII', 0x0C, object_type, object_id)
        
        # Property identifier
        apdu += struct.pack('!BI', 0x19, property_id)
        
        # Array index (optional)
        if array_index is not None:
            apdu += struct.pack('!BI', 0x12, array_index)
        
        # Property value
        if isinstance(value, bool):
            apdu += struct.pack('!BB', 0x91, 1 if value else 0)
        elif isinstance(value, int):
            apdu += struct.pack('!BBI', 0x21, 0x02, value)
        elif isinstance(value, str):
            apdu += struct.pack('!BB', 0x75, len(value)) + value.encode('utf-8')
        else:
            # Default to null
            apdu += struct.pack('!B', 0x00)
        
        return apdu
    
    @staticmethod
    def create_write_property_with_priority(object_id: int, object_type: int,
                                         property_id: int, value: Any, priority: int,
                                         array_index: Optional[int] = None) -> bytes:
        """Create a Write-Property request with priority"""
        # BACnet APDU header
        apdu_type = 0x00  # Confirmed-Request
        service_choice = 0x0F  # WriteProperty
        
        # Create APDU
        apdu = struct.pack('!BB', apdu_type, service_choice)
        
        # Object identifier
        apdu += struct.pack('!BII', 0x0C, object_type, object_id)
        
        # Property identifier
        apdu += struct.pack('!BI', 0x19, property_id)
        
        # Array index (optional)
        if array_index is not None:
            apdu += struct.pack('!BI', 0x12, array_index)
        
        # Priority array
        apdu += struct.pack('!BB', 0x87, priority)  # Priority array
        
        # Property value
        if isinstance(value, bool):
            apdu += struct.pack('!BB', 0x91, 1 if value else 0)
        elif isinstance(value, int):
            apdu += struct.pack('!BBI', 0x21, 0x02, value)
        elif isinstance(value, str):
            apdu += struct.pack('!BB', 0x75, len(value)) + value.encode('utf-8')
        else:
            # Default to null
            apdu += struct.pack('!B', 0x00)
        
        return apdu


class BACnetClient(Base):
    """BACnet client for ICSSploit"""
    
    # Client options (similar to module options)
    options = ['target', 'port', 'device_id', 'timeout']
    
    def __init__(self, name: str, target: str = '', port: int = 47808, device_id: int = 999, 
                 timeout: int = 2):
        """
        Initialize BACnet client
        
        Args:
            name: Name of this target
            target: Target BACnet device IP
            port: BACnet port (default: 47808)
            device_id: Local device ID
            timeout: Socket timeout
        """
        super(BACnetClient, self).__init__(name=name)
        self._target = target
        self._port = port
        self._device_id = device_id
        self._timeout = timeout
        self._connection = None
        self._connected = False
        self.discovered_devices: Dict[str, BACnetDevice] = {}
        self.pending_responses = {}
        self.response_data = {}
        
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
        self._port = int(value)
        
    @property
    def device_id(self):
        """Get device ID"""
        return self._device_id
        
    @device_id.setter
    def device_id(self, value):
        """Set device ID"""
        self._device_id = int(value)
        
    @property
    def timeout(self):
        """Get timeout value"""
        return self._timeout
        
    @timeout.setter
    def timeout(self, value):
        """Set timeout value"""
        self._timeout = int(value)
        
    def connect(self):
        """Connect to BACnet device and verify connectivity"""
        try:
            # Create UDP socket
            self._connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._connection.settimeout(self._timeout)
            self._connection.bind(('0.0.0.0', 0))  # Bind to any available port
            
            # Test connectivity by sending a Who-Is request
            self.logger.info(f"Testing connectivity to {self._target}:{self._port}...")
            
            # Create Who-Is request
            who_is_apdu = BACnetAPDU.create_who_is_request()
            packet = self._create_bacnet_packet(who_is_apdu)
            
            # Send to target
            target_addr = (self._target, self._port)
            self._connection.sendto(packet, target_addr)
            
            # Try to receive a response (with shorter timeout for connection test)
            self._connection.settimeout(2.0)
            try:
                data, addr = self._connection.recvfrom(1024)
                self.logger.info(f"Successfully connected to BACnet device at {self._target}:{self._port}")
                self._connected = True
                return True
            except socket.timeout:
                # No response received, but UDP doesn't guarantee responses
                # Check if we can at least reach the target
                try:
                    # Try a simple ping-like test
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    test_socket.settimeout(1.0)
                    test_socket.sendto(b"", target_addr)
                    test_socket.close()
                    self.logger.info(f"UDP port {self._port} appears to be open on {self._target}")
                    self._connected = True
                    return True
                except Exception:
                    self.logger.error(f"Cannot reach {self._target}:{self._port} - port may be closed or filtered")
                    self._connected = False
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to connect to BACnet device: {e}")
            self._connected = False
            return False
    
    def disconnect(self):
        """Disconnect from BACnet device"""
        if self._connection:
            self._connection.close()
            self._connection = None
            self._connected = False
            self.logger.info("Disconnected from BACnet device")
    
    def _create_bacnet_packet(self, apdu: bytes) -> bytes:
        """Create a BACnet packet with the given APDU"""
        # BACnet/IP header
        version = 0x01
        function = 0x01  # Original-Unicast-NPDU
        
        # NPDU (Network Protocol Data Unit)
        npdu_version = 0x01
        npdu_control = 0x00  # No special control
        
        # Create packet
        packet = struct.pack('!BB', version, function)
        packet += struct.pack('!H', len(apdu) + 4)  # Length
        packet += struct.pack('!BB', npdu_version, npdu_control)
        packet += apdu
        
        return packet
    
    def discover_devices(self, timeout: int = 10) -> List[BACnetDevice]:
        """Discover BACnet devices on the network"""
        if not self._connected:
            if not self.connect():
                return []
        
        self.logger.info(f"Discovering BACnet devices (timeout: {timeout}s)...")
        
        try:
            # Clear previous discoveries
            self.discovered_devices.clear()
            
            # Create Who-Is request
            who_is_apdu = BACnetAPDU.create_who_is_request()
            
            # Create BACnet packet
            packet = self._create_bacnet_packet(who_is_apdu)
            
            # Send to broadcast address
            broadcast_addr = ('255.255.255.255', 47808)
            self._connection.sendto(packet, broadcast_addr)
            
            # Also send directly to target
            target_addr = (self._target, self._port)
            self._connection.sendto(packet, target_addr)
            
            # Wait for responses
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    self._connection.settimeout(1.0)
                    data, addr = self._connection.recvfrom(1024)
                    self._handle_i_am_response(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.debug(f"Error receiving response: {e}")
            
            # Return discovered devices
            devices = list(self.discovered_devices.values())
            self.logger.info(f"Discovered {len(devices)} BACnet devices")
            return devices
            
        except Exception as e:
            self.logger.error(f"Error discovering devices: {e}")
            return []
    
    def _handle_i_am_response(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle I-Am response from device discovery"""
        try:
            # Parse device information from I-Am
            # This is a simplified parser
            device_id = 1  # Placeholder - would parse from APDU
            address = addr[0]
            
            device = BACnetDevice(device_id=device_id, address=address)
            self.discovered_devices[address] = device
                
        except Exception as e:
            self.logger.debug(f"Error parsing I-Am response: {e}")
    
    def read_property(self, object_id: str, property_id: str) -> Optional[Any]:
        """
        Read a property from a BACnet object
        
        Args:
            object_id: Object identifier (e.g., 'analogInput,1')
            property_id: Property identifier (e.g., 'presentValue')
        """
        if not self._connected:
            if not self.connect():
                return None
        
        try:
            # Parse object identifier
            obj_type_str, obj_inst_str = object_id.split(',')
            obj_inst = int(obj_inst_str)
            
            # Get object type enum
            obj_type = BACnetObjectType[obj_type_str.upper().replace('-', '_')].value
            
            # Get property enum - handle common property name variations
            property_mapping = {
                'objectname': 'OBJECT_NAME',
                'presentvalue': 'PRESENT_VALUE',
                'description': 'DESCRIPTION',
                'units': 'UNITS',
                'statusflags': 'STATUS_FLAGS',
                'reliability': 'RELIABILITY',
                'outofservice': 'OUT_OF_SERVICE',
                'vendorname': 'VENDOR_NAME',
                'vendoridentifier': 'VENDOR_IDENTIFIER',
                'modelname': 'MODEL_NAME',
                'firmwarerevision': 'FIRMWARE_REVISION',
                'applicationsoftwareversion': 'APPLICATION_SOFTWARE_VERSION',
                'location': 'LOCATION',
                'protocolversion': 'PROTOCOL_VERSION',
                'protocolrevision': 'PROTOCOL_REVISION',
                'systemstatus': 'SYSTEM_STATUS',
                'maxapdulengthaccepted': 'MAX_APDU_LENGTH_ACCEPTED',
                'segmentationsupported': 'SEGMENTATION_SUPPORTED'
            }
            
            prop_key = property_id.upper().replace('-', '').replace('_', '')
            if prop_key in property_mapping:
                mapped_prop = property_mapping[prop_key]
                prop_id = BACnetProperty[mapped_prop].value
            else:
                # Try direct mapping with common variations
                try:
                    prop_id = BACnetProperty[property_id.upper()].value
                except KeyError:
                    # Try with underscores
                    try:
                        prop_id = BACnetProperty[property_id.upper().replace('-', '_')].value
                    except KeyError:
                        # Try with camelCase to UPPER_CASE conversion
                        import re
                        upper_case = re.sub(r'([a-z])([A-Z])', r'\1_\2', property_id).upper()
                        try:
                            prop_id = BACnetProperty[upper_case].value
                        except KeyError:
                            self.logger.error(f"Property '{property_id}' not found in BACnetProperty enum")
                            return None
            
            # Create read request
            read_apdu = BACnetAPDU.create_read_property_request(obj_inst, obj_type, prop_id)
            
            # Create BACnet packet
            packet = self._create_bacnet_packet(read_apdu)
            
            # Send request
            target_addr = (self._target, self._port)
            self._connection.sendto(packet, target_addr)
            
            # Wait for response
            try:
                self._connection.settimeout(3.0)
                data, addr = self._connection.recvfrom(1024)
                return self._parse_read_response(data)
            except socket.timeout:
                self.logger.debug(f"No response received for {object_id}.{property_id}")
                return None
            except Exception as e:
                self.logger.error(f"Error reading property: {e}")
                return None
            
        except Exception as e:
            self.logger.error(f"Error reading property: {e}")
            return None
    
    def _parse_read_response(self, data: bytes) -> Optional[str]:
        """Parse BACnet ReadProperty response"""
        try:
            # Parse BACnet ReadProperty response
            if len(data) < 6:
                return None
            
            # Extract APDU
            apdu_start = 6  # Skip BACnet/IP header
            apdu = data[apdu_start:]
            
            if len(apdu) < 4:
                return None
            
            # This is a simplified parser - in a real implementation you'd parse the full APDU
            return self._parse_bacnet_value(apdu)
                    
        except Exception as e:
            self.logger.error(f"Error parsing read response: {e}")
            return None
    
    def _parse_bacnet_value(self, apdu: bytes) -> str:
        """Parse BACnet value from APDU"""
        try:
            # This is a simplified parser
            # In a real implementation, you'd parse the full BACnet APDU structure
            
            # Look for common BACnet data types
            if len(apdu) >= 2:
                # Try to extract string values
                for i in range(len(apdu) - 1):
                    if apdu[i] == 0x75:  # CharacterString tag
                        length = apdu[i + 1]
                        if i + 2 + length <= len(apdu):
                            value = apdu[i + 2:i + 2 + length].decode('utf-8', errors='ignore')
                            return value
                
                # Try to extract numeric values
                for i in range(len(apdu) - 3):
                    if apdu[i] == 0x21:  # UnsignedInteger tag
                        if i + 4 <= len(apdu):
                            value = struct.unpack('!I', apdu[i + 1:i + 5])[0]
                            return str(value)
                    elif apdu[i] == 0x44:  # Real tag
                        if i + 5 <= len(apdu):
                            value = struct.unpack('!f', apdu[i + 1:i + 5])[0]
                            return str(value)
            
            # If we can't parse it, return a hex representation
            return f"0x{apdu.hex()[:20]}..."
            
        except Exception as e:
            return f"<parse_error: {e}>"
    
    def write_property(self, object_id: str, property_id: str, value: Any) -> bool:
        """
        Write a property to a BACnet object
        
        Args:
            object_id: Object identifier
            property_id: Property identifier
            value: Value to write
        """
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            # Parse object identifier
            obj_type_str, obj_inst_str = object_id.split(',')
            obj_inst = int(obj_inst_str)
            
            # Get object type enum
            obj_type = BACnetObjectType[obj_type_str.upper().replace('-', '_')].value
            
            # Get property enum
            prop_id = BACnetProperty[property_id.upper()].value
            
            # Create write request
            write_apdu = BACnetAPDU.create_write_property_request(obj_inst, obj_type, prop_id, value)
            
            # Create BACnet packet
            packet = self._create_bacnet_packet(write_apdu)
            
            # Send request
            target_addr = (self._target, self._port)
            self._connection.sendto(packet, target_addr)
            
            self.logger.info(f"Writing {value} to {property_id} of {object_id}")
            
            # Wait for response
            try:
                self._connection.settimeout(3.0)
                data, addr = self._connection.recvfrom(1024)
                return True  # Assume success if we get a response
            except socket.timeout:
                self.logger.debug("No response received for write operation")
                return False
            except Exception as e:
                self.logger.error(f"Error writing property: {e}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error writing property: {e}")
            return False
    
    def write_command(self, object_id: str, command: str, value: Any = None, 
                     priority: int = 16) -> bool:
        """
        Write a command to a BACnet object
        
        Args:
            object_id: Object identifier (e.g., 'analogOutput,1')
            command: Command to execute
            value: Value for the command
            priority: Priority level (1-16, 16 is highest)
        """
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            # Parse object identifier
            obj_type_str, obj_inst_str = object_id.split(',')
            obj_inst = int(obj_inst_str)
            obj_type = BACnetObjectType[obj_type_str.upper().replace('-', '_')].value
            
            # Create command based on type
            if command.lower() == 'set_value':
                return self._write_present_value(obj_type, obj_inst, value, priority)
            elif command.lower() == 'enable':
                return self._write_out_of_service(obj_type, obj_inst, False)
            elif command.lower() == 'disable':
                return self._write_out_of_service(obj_type, obj_inst, True)
            else:
                self.logger.error(f"Unknown command: {command}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error executing command: {e}")
            return False
    
    def _write_present_value(self, obj_type: int, obj_inst: int, 
                           value: Any, priority: int) -> bool:
        """Write present value with priority"""
        try:
            # Create write request with priority
            write_apdu = BACnetAPDU.create_write_property_with_priority(
                obj_inst, obj_type, BACnetProperty.PRESENT_VALUE.value, value, priority
            )
            
            packet = self._create_bacnet_packet(write_apdu)
            target_addr = (self._target, self._port)
            self._connection.sendto(packet, target_addr)
            
            self.logger.info(f"Writing value {value} with priority {priority} to {obj_type},{obj_inst}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error writing present value: {e}")
            return False
    
    def _write_out_of_service(self, obj_type: int, obj_inst: int, 
                            out_of_service: bool) -> bool:
        """Enable/disable an object"""
        try:
            write_apdu = BACnetAPDU.create_write_property_request(
                obj_inst, obj_type, BACnetProperty.OUT_OF_SERVICE.value, out_of_service
            )
            
            packet = self._create_bacnet_packet(write_apdu)
            target_addr = (self._target, self._port)
            self._connection.sendto(packet, target_addr)
            
            status = "disabled" if out_of_service else "enabled"
            self.logger.info(f"Object {obj_type},{obj_inst} {status}")
            return True
                
        except Exception as e:
            self.logger.error(f"Error setting out of service: {e}")
            return False
    
    def get_target_info(self) -> Tuple[str, str, str, str, str, str]:
        """
        Get target device information
        
        Returns:
            Tuple of (device_name, vendor_name, model_name, firmware_version, 
                     system_status, max_apdu_length)
        """
        try:
            device_name = self.read_property('device,1', 'objectName') or 'Unknown'
            vendor_name = self.read_property('device,1', 'vendorName') or 'Unknown'
            model_name = self.read_property('device,1', 'modelName') or 'Unknown'
            firmware_version = self.read_property('device,1', 'firmwareRevision') or 'Unknown'
            system_status = self.read_property('device,1', 'systemStatus') or 'Unknown'
            max_apdu_length = self.read_property('device,1', 'maxApduLengthAccepted') or 'Unknown'
            
            return (device_name, vendor_name, model_name, firmware_version, 
                   system_status, max_apdu_length)
            
        except Exception as e:
            self.logger.error(f"Error getting target info: {e}")
            return ('Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown')
    
    def enumerate_device(self) -> Dict[str, List[Tuple[int, str]]]:
        """
        Enumerate device objects
        
        Returns:
            Dictionary mapping object types to lists of (instance, name) tuples
        """
        result = {}
        
        # Enumerate objects by type
        object_types = [
            'analogInput', 'analogOutput', 'analogValue',
            'binaryInput', 'binaryOutput', 'binaryValue',
            'multiStateInput', 'multiStateOutput', 'multiStateValue'
        ]
        
        for obj_type in object_types:
            found_objects = []
            
            # Check first 10 instances of each type
            for instance in range(1, 11):
                try:
                    obj_id = f"{obj_type},{instance}"
                    name = self.read_property(obj_id, 'objectName')
                    if name is not None:
                        found_objects.append((instance, name))
                except:
                    continue
            
            if found_objects:
                result[obj_type] = found_objects
        
        return result
    
    def check_permissions(self, object_id: str = 'device,1') -> Dict[str, bool]:
        """
        Check read/write permissions for common properties
        
        Args:
            object_id: Object identifier to test
            
        Returns:
            Dictionary mapping property names to read/write permission status
        """
        permissions = {}
        
        # Common properties to test
        test_properties = [
            'objectName', 'presentValue', 'description', 'units',
            'statusFlags', 'reliability', 'outOfService'
        ]
        
        for prop in test_properties:
            try:
                value = self.read_property(object_id, prop)
                permissions[f"{prop}_read"] = value is not None
            except Exception as e:
                permissions[f"{prop}_read"] = False
        
        # Test write permissions (be careful!)
        write_test_properties = [
            ('outOfService', True),  # Safe to test
            ('description', 'Test Write')  # Safe to test
        ]
        
        for prop, test_value in write_test_properties:
            try:
                success = self.write_property(object_id, prop, test_value)
                permissions[f"{prop}_write"] = success
                # Try to restore original value if possible
                if prop == 'outOfService' and success:
                    self.write_property(object_id, prop, False)
            except Exception as e:
                permissions[f"{prop}_write"] = False
        
        return permissions 