#!/usr/bin/env python3
"""
DNP3 Protocol Implementation for ICSSploit
A Python implementation of DNP3 (IEEE 1815) protocol structures and utilities
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
import struct
import logging

# DNP3 Function Codes
class DNP3FunctionCode(Enum):
    """DNP3 Application Layer Function Codes"""
    CONFIRM = 0x00
    READ = 0x01
    WRITE = 0x02
    SELECT = 0x03
    OPERATE = 0x04
    DIRECT_OPERATE = 0x05
    DIRECT_OPERATE_NR = 0x06
    IMMED_FREEZE = 0x07
    IMMED_FREEZE_NR = 0x08
    FREEZE_CLEAR = 0x09
    FREEZE_CLEAR_NR = 0x0A
    FREEZE_AT_TIME = 0x0B
    FREEZE_AT_TIME_NR = 0x0C
    COLD_RESTART = 0x0D
    WARM_RESTART = 0x0E
    INITIALIZE_DATA = 0x0F
    INITIALIZE_APPL = 0x10
    START_APPL = 0x11
    STOP_APPL = 0x12
    SAVE_CONFIG = 0x13
    ENABLE_UNSOLICITED = 0x14
    DISABLE_UNSOLICITED = 0x15
    ASSIGN_CLASS = 0x16
    DELAY_MEASURE = 0x17
    RECORD_CURRENT_TIME = 0x18
    OPEN_FILE = 0x19
    CLOSE_FILE = 0x1A
    DELETE_FILE = 0x1B
    GET_FILE_INFO = 0x1C
    AUTHENTICATE = 0x1D
    ABORT_FILE = 0x1E
    ACTIVATE_CONFIG = 0x1F
    AUTHENTICATION_REQUEST = 0x20
    AUTHENTICATION_ERROR = 0x21
    RESPONSE = 0x81
    UNSOLICITED_RESPONSE = 0x82
    AUTHENTICATION_RESPONSE = 0x83

# DNP3 Object Groups
class DNP3ObjectGroup(Enum):
    """DNP3 Object Groups"""
    BINARY_INPUT = 1
    BINARY_INPUT_EVENT = 2
    DOUBLE_BIT_BINARY_INPUT = 3
    DOUBLE_BIT_BINARY_INPUT_EVENT = 4
    BINARY_OUTPUT = 10
    BINARY_OUTPUT_EVENT = 11
    BINARY_OUTPUT_COMMAND = 12
    BINARY_COUNTER = 20
    FROZEN_COUNTER = 21
    COUNTER_EVENT = 22
    FROZEN_COUNTER_EVENT = 23
    ANALOG_INPUT = 30
    FROZEN_ANALOG_INPUT = 31
    ANALOG_INPUT_EVENT = 32
    FROZEN_ANALOG_INPUT_EVENT = 33
    ANALOG_INPUT_REPORTING_DEADBAND = 34
    ANALOG_OUTPUT = 40
    ANALOG_OUTPUT_EVENT = 42
    ANALOG_OUTPUT_COMMAND = 41
    TIME_AND_DATE = 50
    TIME_AND_DATE_CTO = 51
    TIME_DELAY = 52
    CLASS_DATA = 60
    FILE_CONTROL = 70
    INTERNAL_INDICATIONS = 80
    OCTET_STRING = 110
    OCTET_STRING_EVENT = 111
    VIRTUAL_TERMINAL_OUTPUT = 112
    VIRTUAL_TERMINAL_EVENT = 113
    AUTHENTICATION_CHALLENGE = 120
    AUTHENTICATION_REPLY = 121
    AUTHENTICATION_AGGRESSIVE_MODE_REQUEST = 122
    AUTHENTICATION_KEY_STATUS = 123
    AUTHENTICATION_KEY_CHANGE = 124
    AUTHENTICATION_ERROR = 125
    AUTHENTICATION_HMAC = 126

# DNP3 Variations for common object groups
class DNP3Variation(Enum):
    """Common DNP3 Object Variations"""
    # Binary Input variations
    BINARY_INPUT_PACKED = (1, 1)
    BINARY_INPUT_WITH_FLAGS = (1, 2)
    
    # Binary Output variations
    BINARY_OUTPUT_PACKED = (10, 1)
    BINARY_OUTPUT_WITH_FLAGS = (10, 2)
    
    # Analog Input variations
    ANALOG_INPUT_32BIT = (30, 1)
    ANALOG_INPUT_16BIT = (30, 2)
    ANALOG_INPUT_32BIT_NO_FLAG = (30, 3)
    ANALOG_INPUT_16BIT_NO_FLAG = (30, 4)
    ANALOG_INPUT_FLOAT = (30, 5)
    ANALOG_INPUT_DOUBLE = (30, 6)
    
    # Counter variations
    COUNTER_32BIT = (20, 1)
    COUNTER_16BIT = (20, 2)
    COUNTER_32BIT_DELTA = (20, 3)
    COUNTER_16BIT_DELTA = (20, 4)
    COUNTER_32BIT_NO_FLAG = (20, 5)
    COUNTER_16BIT_NO_FLAG = (20, 6)

# DNP3 Quality Flags
class DNP3QualityFlags(Enum):
    """DNP3 Quality Flags for different data types"""
    # Binary Input Quality Flags
    BINARY_ONLINE = 0x01
    BINARY_RESTART = 0x02
    BINARY_COMM_LOST = 0x04
    BINARY_REMOTE_FORCED = 0x08
    BINARY_LOCAL_FORCED = 0x10
    BINARY_CHATTER_FILTER = 0x20
    BINARY_RESERVED = 0x40
    BINARY_STATE = 0x80
    
    # Analog Quality Flags
    ANALOG_ONLINE = 0x01
    ANALOG_RESTART = 0x02
    ANALOG_COMM_LOST = 0x04
    ANALOG_REMOTE_FORCED = 0x08
    ANALOG_LOCAL_FORCED = 0x10
    ANALOG_OVER_RANGE = 0x20
    ANALOG_REFERENCE_ERR = 0x40
    ANALOG_RESERVED = 0x80

# DNP3 Internal Indication Flags
class DNP3InternalIndication(Enum):
    """DNP3 Internal Indication Flags"""
    ALL_STATIONS = 0x0001
    CLASS_1_EVENTS = 0x0002
    CLASS_2_EVENTS = 0x0004
    CLASS_3_EVENTS = 0x0008
    NEED_TIME = 0x0010
    LOCAL_CONTROL = 0x0020
    DEVICE_TROUBLE = 0x0040
    DEVICE_RESTART = 0x0080
    NO_FUNC_CODE_SUPPORT = 0x0100
    OBJECT_UNKNOWN = 0x0200
    PARAMETER_ERROR = 0x0400
    EVENT_BUFFER_OVERFLOW = 0x0800
    ALREADY_EXECUTING = 0x1000
    CONFIG_CORRUPT = 0x2000
    RESERVED_2 = 0x4000
    RESERVED_1 = 0x8000

@dataclass
class DNP3DataLinkHeader:
    """DNP3 Data Link Layer Header"""
    start1: int = 0x05  # Start byte 1
    start2: int = 0x64  # Start byte 2
    length: int = 0     # Length of frame (excluding start bytes and CRC)
    control: int = 0    # Control byte
    destination: int = 0 # Destination address
    source: int = 0     # Source address
    
    def pack(self) -> bytes:
        """Pack header into bytes"""
        return struct.pack('<BBBBHH', 
                          self.start1, self.start2, self.length, 
                          self.control, self.destination, self.source)
    
    @classmethod
    def unpack(cls, data: bytes) -> 'DNP3DataLinkHeader':
        """Unpack header from bytes"""
        start1, start2, length, control, dest, src = struct.unpack('<BBBBHH', data[:8])
        return cls(start1, start2, length, control, dest, src)

@dataclass
class DNP3TransportHeader:
    """DNP3 Transport Layer Header"""
    fin: bool = True    # Final segment
    fir: bool = True    # First segment
    sequence: int = 0   # Sequence number (0-63)
    
    def pack(self) -> bytes:
        """Pack transport header into bytes"""
        control = (self.fin << 7) | (self.fir << 6) | (self.sequence & 0x3F)
        return struct.pack('<B', control)
    
    @classmethod
    def unpack(cls, data: bytes) -> 'DNP3TransportHeader':
        """Unpack transport header from bytes"""
        control = struct.unpack('<B', data[:1])[0]
        fin = bool(control & 0x80)
        fir = bool(control & 0x40)
        sequence = control & 0x3F
        return cls(fin, fir, sequence)

@dataclass
class DNP3ApplicationHeader:
    """DNP3 Application Layer Header"""
    control: int = 0        # Application control byte
    function_code: int = 0  # Function code
    
    def pack(self) -> bytes:
        """Pack application header into bytes"""
        return struct.pack('<BB', self.control, self.function_code)
    
    @classmethod
    def unpack(cls, data: bytes) -> 'DNP3ApplicationHeader':
        """Unpack application header from bytes"""
        control, function_code = struct.unpack('<BB', data[:2])
        return cls(control, function_code)

@dataclass
class DNP3ObjectHeader:
    """DNP3 Object Header"""
    group: int = 0          # Object group
    variation: int = 0      # Object variation
    qualifier: int = 0      # Qualifier code
    range_field: bytes = b'' # Range/Index field (variable length)
    
    def pack(self) -> bytes:
        """Pack object header into bytes"""
        return struct.pack('<BBB', self.group, self.variation, self.qualifier) + self.range_field
    
    @classmethod
    def unpack(cls, data: bytes) -> tuple['DNP3ObjectHeader', int]:
        """Unpack object header from bytes, returns (header, bytes_consumed)"""
        if len(data) < 3:
            raise ValueError("Insufficient data for object header")
        
        group, variation, qualifier = struct.unpack('<BBB', data[:3])
        
        # Determine range field length based on qualifier
        range_length = cls._get_range_field_length(qualifier)
        if len(data) < 3 + range_length:
            raise ValueError("Insufficient data for range field")
        
        range_field = data[3:3 + range_length]
        return cls(group, variation, qualifier, range_field), 3 + range_length
    
    @staticmethod
    def _get_range_field_length(qualifier: int) -> int:
        """Get the length of range field based on qualifier code"""
        qualifier_type = qualifier & 0x70
        if qualifier_type == 0x00:  # 8-bit start/stop
            return 2
        elif qualifier_type == 0x10:  # 16-bit start/stop
            return 4
        elif qualifier_type == 0x20:  # 32-bit start/stop
            return 8
        elif qualifier_type == 0x30:  # 8-bit absolute address
            return 1
        elif qualifier_type == 0x40:  # 16-bit absolute address
            return 2
        elif qualifier_type == 0x50:  # 32-bit absolute address
            return 4
        elif qualifier_type == 0x60:  # No range field
            return 0
        else:
            return 0

@dataclass
class DNP3Point:
    """Represents a DNP3 data point"""
    index: int
    value: Any
    quality: int = 0
    timestamp: Optional[int] = None
    
    def __str__(self) -> str:
        return f"Point[{self.index}]: {self.value} (Q:{self.quality:02X})"

class DNP3Utils:
    """Utility functions for DNP3 protocol"""
    
    @staticmethod
    def calculate_crc(data: bytes) -> int:
        """Calculate DNP3 CRC-16"""
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return crc & 0xFFFF
    
    @staticmethod
    def add_crc_to_frame(data: bytes) -> bytes:
        """Add CRC to DNP3 frame"""
        result = bytearray()
        
        # Process data in 16-byte blocks (DNP3 CRC block size)
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            result.extend(block)
            
            # Calculate and append CRC for this block
            crc = DNP3Utils.calculate_crc(block)
            result.extend(struct.pack('<H', crc))
        
        return bytes(result)
    
    @staticmethod
    def remove_crc_from_frame(data: bytes) -> bytes:
        """Remove CRC from DNP3 frame and verify integrity"""
        result = bytearray()
        
        # Process data in 18-byte blocks (16 data + 2 CRC)
        i = 0
        while i < len(data):
            if i + 18 <= len(data):
                # Full block
                block = data[i:i+16]
                crc_bytes = data[i+16:i+18]
                expected_crc = struct.unpack('<H', crc_bytes)[0]
                
                # Verify CRC
                calculated_crc = DNP3Utils.calculate_crc(block)
                if calculated_crc != expected_crc:
                    raise ValueError(f"CRC mismatch at block {i//18}: expected {expected_crc:04X}, got {calculated_crc:04X}")
                
                result.extend(block)
                i += 18
            else:
                # Partial block at end
                remaining = len(data) - i
                if remaining >= 2:  # At least CRC present
                    block = data[i:i+remaining-2]
                    crc_bytes = data[i+remaining-2:i+remaining]
                    expected_crc = struct.unpack('<H', crc_bytes)[0]
                    
                    # Verify CRC
                    calculated_crc = DNP3Utils.calculate_crc(block)
                    if calculated_crc != expected_crc:
                        raise ValueError(f"CRC mismatch in final block: expected {expected_crc:04X}, got {calculated_crc:04X}")
                    
                    result.extend(block)
                break
        
        return bytes(result)
    
    @staticmethod
    def create_read_request(source: int, destination: int, objects: List[tuple]) -> bytes:
        """
        Create a DNP3 read request frame
        
        Args:
            source: Source address
            destination: Destination address  
            objects: List of (group, variation, start_index, stop_index) tuples
        
        Returns:
            Complete DNP3 frame with CRC
        """
        # Application layer
        app_header = DNP3ApplicationHeader(control=0xC0, function_code=DNP3FunctionCode.READ.value)
        app_data = app_header.pack()
        
        # Add object headers
        for group, variation, start_idx, stop_idx in objects:
            obj_header = DNP3ObjectHeader(
                group=group,
                variation=variation,
                qualifier=0x00,  # 8-bit start/stop
                range_field=struct.pack('<BB', start_idx, stop_idx)
            )
            app_data += obj_header.pack()
        
        # Transport layer
        transport_header = DNP3TransportHeader(fin=True, fir=True, sequence=0)
        transport_data = transport_header.pack() + app_data
        
        # Data link layer
        dl_header = DNP3DataLinkHeader(
            length=len(transport_data),
            control=0x44,  # Unconfirmed user data
            destination=destination,
            source=source
        )
        
        frame = dl_header.pack() + transport_data
        
        # Add CRC
        return DNP3Utils.add_crc_to_frame(frame)
    
    @staticmethod
    def parse_response(data: bytes) -> Dict[str, Any]:
        """
        Parse a DNP3 response frame
        
        Args:
            data: Raw DNP3 frame data
            
        Returns:
            Dictionary containing parsed response data
        """
        try:
            # Remove CRC and get clean data
            clean_data = DNP3Utils.remove_crc_from_frame(data)
            
            # Parse data link header
            if len(clean_data) < 8:
                return {"error": "Frame too short for data link header"}
            
            dl_header = DNP3DataLinkHeader.unpack(clean_data[:8])
            
            # Parse transport header
            if len(clean_data) < 9:
                return {"error": "Frame too short for transport header"}
            
            transport_header = DNP3TransportHeader.unpack(clean_data[8:9])
            
            # Parse application header
            if len(clean_data) < 11:
                return {"error": "Frame too short for application header"}
            
            app_header = DNP3ApplicationHeader.unpack(clean_data[9:11])
            
            # Parse objects (simplified)
            objects = []
            offset = 11
            
            while offset < len(clean_data):
                try:
                    obj_header, consumed = DNP3ObjectHeader.unpack(clean_data[offset:])
                    objects.append({
                        "group": obj_header.group,
                        "variation": obj_header.variation,
                        "qualifier": obj_header.qualifier
                    })
                    offset += consumed
                    
                    # Skip object data for now (would need variation-specific parsing)
                    break
                except Exception as e:
                    break
            
            return {
                "data_link": {
                    "source": dl_header.source,
                    "destination": dl_header.destination,
                    "control": dl_header.control
                },
                "transport": {
                    "fin": transport_header.fin,
                    "fir": transport_header.fir,
                    "sequence": transport_header.sequence
                },
                "application": {
                    "control": app_header.control,
                    "function_code": app_header.function_code
                },
                "objects": objects
            }
            
        except Exception as e:
            return {"error": f"Parse error: {str(e)}"}

# DNP3 Device Information Structure
@dataclass
class DNP3DeviceInfo:
    """Information about a DNP3 device"""
    address: int
    vendor_name: str = "Unknown"
    device_name: str = "Unknown"
    software_version: str = "Unknown"
    hardware_version: str = "Unknown"
    location: str = "Unknown"
    device_id: str = "Unknown"
    device_function: str = "Unknown"
    serial_number: str = "Unknown"
    supports_unsolicited: bool = False
    max_tx_fragment_size: int = 2048
    max_rx_fragment_size: int = 2048
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for easy serialization"""
        return {
            "address": self.address,
            "vendor_name": self.vendor_name,
            "device_name": self.device_name,
            "software_version": self.software_version,
            "hardware_version": self.hardware_version,
            "location": self.location,
            "device_id": self.device_id,
            "device_function": self.device_function,
            "serial_number": self.serial_number,
            "supports_unsolicited": self.supports_unsolicited,
            "max_tx_fragment_size": self.max_tx_fragment_size,
            "max_rx_fragment_size": self.max_rx_fragment_size
        }

# Common DNP3 object configurations for enumeration
DNP3_COMMON_OBJECTS = [
    # Binary Inputs
    (DNP3ObjectGroup.BINARY_INPUT.value, 1, 0, 255),  # Binary Input - Packed format
    (DNP3ObjectGroup.BINARY_INPUT.value, 2, 0, 255),  # Binary Input - With flags
    
    # Binary Outputs  
    (DNP3ObjectGroup.BINARY_OUTPUT.value, 1, 0, 255), # Binary Output - Packed format
    (DNP3ObjectGroup.BINARY_OUTPUT.value, 2, 0, 255), # Binary Output - With flags
    
    # Analog Inputs
    (DNP3ObjectGroup.ANALOG_INPUT.value, 1, 0, 255),  # Analog Input - 32-bit with flag
    (DNP3ObjectGroup.ANALOG_INPUT.value, 2, 0, 255),  # Analog Input - 16-bit with flag
    (DNP3ObjectGroup.ANALOG_INPUT.value, 3, 0, 255),  # Analog Input - 32-bit without flag
    (DNP3ObjectGroup.ANALOG_INPUT.value, 4, 0, 255),  # Analog Input - 16-bit without flag
    
    # Counters
    (DNP3ObjectGroup.BINARY_COUNTER.value, 1, 0, 255), # Counter - 32-bit with flag
    (DNP3ObjectGroup.BINARY_COUNTER.value, 2, 0, 255), # Counter - 16-bit with flag
    
    # Class data objects for events
    (DNP3ObjectGroup.CLASS_DATA.value, 1, 0, 0),      # Class 1 data
    (DNP3ObjectGroup.CLASS_DATA.value, 2, 0, 0),      # Class 2 data  
    (DNP3ObjectGroup.CLASS_DATA.value, 3, 0, 0),      # Class 3 data
]

# DNP3 Error codes
DNP3_ERROR_CODES = {
    0x00: "Success",
    0x01: "Timeout", 
    0x02: "No permission",
    0x03: "Format error",
    0x04: "Not supported",
    0x05: "Already executing",
    0x06: "Unknown destination",
    0x07: "Unknown source",
    0x08: "Unknown object",
    0x09: "Unknown function",
    0x0A: "Local control",
    0x0B: "Too many operations",
    0x0C: "Not authorized",
    0x0D: "Automation inhibit",
    0x0E: "Processing limited",
    0x0F: "Out of range"
}
