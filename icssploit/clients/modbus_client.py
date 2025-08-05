#!/usr/bin/env python3
"""
Modbus Client for ICSSploit
A Python client to interact with Modbus devices using pymodbus
"""

import asyncio
import sys
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from icssploit.clients.base import Base

# Import pymodbus components
try:
    from pymodbus.client import ModbusTcpClient, ModbusSerialClient
    from pymodbus.exceptions import ModbusException, ConnectionException
    from pymodbus.pdu import ExceptionResponse
    PYMODBUS_AVAILABLE = True
except ImportError as e:
    print(f"Error: pymodbus not installed or import failed: {e}")
    print("Please install with: pip install pymodbus[serial]")
    PYMODBUS_AVAILABLE = False


class ModbusFunctionCode(Enum):
    """Modbus function codes"""
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10
    READ_WRITE_MULTIPLE_REGISTERS = 0x17
    DIAGNOSTIC = 0x08
    GET_COM_EVENT_COUNTER = 0x0B
    GET_COM_EVENT_LOG = 0x0C
    REPORT_SLAVE_ID = 0x11
    READ_FILE_RECORD = 0x14
    WRITE_FILE_RECORD = 0x15
    MASK_WRITE_REGISTER = 0x16
    READ_FIFO_QUEUE = 0x18
    ENCAPSULATED_INTERFACE_TRANSPORT = 0x2B


class ModbusExceptionCode(Enum):
    """Modbus exception codes"""
    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    SLAVE_DEVICE_FAILURE = 0x04
    ACKNOWLEDGE = 0x05
    SLAVE_DEVICE_BUSY = 0x06
    MEMORY_PARITY_ERROR = 0x08
    GATEWAY_PATH_UNAVAILABLE = 0x0A
    GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND = 0x0B


@dataclass
class ModbusDevice:
    """Represents a Modbus device"""
    unit_id: int
    address: str
    port: int = 502
    device_type: str = "TCP"
    baud_rate: int = 9600
    data_bits: int = 8
    stop_bits: int = 1
    parity: str = "N"


class ModbusClient(Base):
    """Modbus client for ICSSploit"""
    
    def __init__(self, name: str, ip: str, port: int = 502, unit_id: int = 1,
                 device_type: str = "TCP", timeout: int = 2,
                 serial_port: str = None, baud_rate: int = 9600,
                 data_bits: int = 8, stop_bits: int = 1, parity: str = "N"):
        """
        Initialize Modbus client
        
        Args:
            name: Name of this target
            ip: Target Modbus device IP (for TCP) or serial port (for RTU)
            port: Modbus port (default: 502)
            unit_id: Modbus unit ID (default: 1)
            device_type: Device type - TCP or RTU (default: TCP)
            timeout: Socket timeout
            serial_port: Serial port for RTU mode
            baud_rate: Baud rate for RTU mode
            data_bits: Data bits for RTU mode
            stop_bits: Stop bits for RTU mode
            parity: Parity for RTU mode
        """
        super(ModbusClient, self).__init__(name=name)
        self._ip = ip
        self._port = port
        self._unit_id = unit_id
        self._device_type = device_type.upper()
        self._timeout = timeout
        self._serial_port = serial_port
        self._baud_rate = baud_rate
        self._data_bits = data_bits
        self._stop_bits = stop_bits
        self._parity = parity
        
        # pymodbus client objects
        self._tcp_client = None
        self._serial_client = None
        self._client = None
        self._connected = False
        
        if not PYMODBUS_AVAILABLE:
            self.logger.error("pymodbus library not available. Please install with: pip install pymodbus[serial]")
    
    def connect(self) -> bool:
        """Connect to Modbus device and verify connectivity"""
        try:
            self.logger.info(f"Testing connectivity to {self._ip}:{self._port}...")
            
            if self._device_type == "TCP":
                # Create TCP client
                self._tcp_client = ModbusTcpClient(host=self._ip, port=self._port, timeout=self._timeout)
                self._client = self._tcp_client
            else:
                # Create RTU client
                self._serial_client = ModbusSerialClient(
                    method='rtu',
                    port=self._serial_port or self._ip,
                    baudrate=self._baud_rate,
                    bytesize=self._data_bits,
                    stopbits=self._stop_bits,
                    parity=self._parity,
                    timeout=self._timeout
                )
                self._client = self._serial_client
            
            if self._client:
                # Try to establish connection
                self._connected = self._client.connect()
                if self._connected:
                    # Test if we can actually communicate with the device
                    try:
                        # Try to read a single register to verify communication
                        result = self._call_modbus_method('read_holding_registers', 0, count=1, unit_id=self._unit_id)
                        if result and not result.isError():
                            self.logger.info(f"✓ Successfully connected to Modbus device at {self._ip}:{self._port}")
                            return True
                        else:
                            self.logger.warning(f"⚠ Connected to {self._ip}:{self._port} but device may not be responding")
                            return True  # Still consider connected, but with warning
                    except Exception as e:
                        self.logger.error(f"✗ Connected to {self._ip}:{self._port} but communication failed: {e}")
                        self._connected = False
                        return False
                else:
                    self.logger.error(f"✗ Failed to connect to Modbus device at {self._ip}:{self._port} - port may be closed")
                    return False
            return False
            
        except Exception as e:
            self.logger.error(f"✗ Failed to connect to Modbus device: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from Modbus device"""
        if self._client and self._connected:
            self._client.close()
            self._connected = False
            self.logger.info("Disconnected from Modbus device")
    
    def discover_devices(self, start_unit_id: int = 1, end_unit_id: int = 247) -> List[ModbusDevice]:
        """Discover Modbus devices on the network"""
        devices = []
        
        if not self.connect():
            return devices
        
        try:
            self.logger.info(f"Scanning for Modbus devices...")
            
            for unit_id in range(start_unit_id, end_unit_id + 1):
                try:
                    # Try to read device ID or a single register
                    result = self._call_modbus_method('read_holding_registers', 0, count=1, unit_id=unit_id)
                    
                    if result and not result.isError():
                        device = ModbusDevice(
                            unit_id=unit_id,
                            address=self._ip,
                            port=self._port,
                            device_type=self._device_type,
                            baud_rate=self._baud_rate,
                            data_bits=self._data_bits,
                            stop_bits=self._stop_bits,
                            parity=self._parity
                        )
                        devices.append(device)
                        self.logger.info(f"Found device with unit ID: {unit_id}")
                        
                except Exception:
                    # Device not responding or doesn't exist
                    pass
                    
        finally:
            self.disconnect()
        
        return devices
    
    def read_coils(self, start_address: int, count: int) -> Optional[List[bool]]:
        """Read coils (0x01)"""
        if not self.connect():
            return None
        
        try:
            result = self._call_modbus_method('read_coils', start_address, count=count, unit_id=self._unit_id)
            if result and not result.isError():
                return result.bits[:count]
            return None
        except Exception as e:
            self.logger.error(f"Error reading coils: {e}")
            return None
        finally:
            self.disconnect()
    
    def read_discrete_inputs(self, start_address: int, count: int) -> Optional[List[bool]]:
        """Read discrete inputs (0x02)"""
        if not self.connect():
            return None
        
        try:
            result = self._call_modbus_method('read_discrete_inputs', start_address, count=count, unit_id=self._unit_id)
            if result and not result.isError():
                return result.bits[:count]
            return None
        except Exception as e:
            self.logger.error(f"Error reading discrete inputs: {e}")
            return None
        finally:
            self.disconnect()
    
    def read_holding_registers(self, start_address: int, count: int) -> Optional[List[int]]:
        """Read holding registers (0x03)"""
        if not self.connect():
            return None
        
        try:
            result = self._call_modbus_method('read_holding_registers', start_address, count=count, unit_id=self._unit_id)
            if result and not result.isError():
                return result.registers
            return None
        except Exception as e:
            self.logger.error(f"Error reading holding registers: {e}")
            return None
        finally:
            self.disconnect()
    
    def read_input_registers(self, start_address: int, count: int) -> Optional[List[int]]:
        """Read input registers (0x04)"""
        if not self.connect():
            return None
        
        try:
            result = self._call_modbus_method('read_input_registers', start_address, count=count, unit_id=self._unit_id)
            if result and not result.isError():
                return result.registers
            return None
        except Exception as e:
            self.logger.error(f"Error reading input registers: {e}")
            return None
        finally:
            self.disconnect()
    
    def write_single_coil(self, address: int, value: bool) -> bool:
        """Write single coil (0x05)"""
        if not self.connect():
            return False
        
        try:
            result = self._call_modbus_method('write_coil', address, value, unit_id=self._unit_id)
            return result and not result.isError()
        except Exception as e:
            self.logger.error(f"Error writing single coil: {e}")
            return False
        finally:
            self.disconnect()
    
    def write_single_register(self, address: int, value: int) -> bool:
        """Write single register (0x06)"""
        if not self.connect():
            return False
        
        try:
            result = self._call_modbus_method('write_register', address, value, unit_id=self._unit_id)
            return result and not result.isError()
        except Exception as e:
            self.logger.error(f"Error writing single register: {e}")
            return False
        finally:
            self.disconnect()
    
    def write_multiple_coils(self, start_address: int, values: List[bool]) -> bool:
        """Write multiple coils (0x0F)"""
        if not self.connect():
            return False
        
        try:
            result = self._call_modbus_method('write_coils', start_address, values, unit_id=self._unit_id)
            return result and not result.isError()
        except Exception as e:
            self.logger.error(f"Error writing multiple coils: {e}")
            return False
        finally:
            self.disconnect()
    
    def write_multiple_registers(self, start_address: int, values: List[int]) -> bool:
        """Write multiple registers (0x10)"""
        if not self.connect():
            return False
        
        try:
            result = self._call_modbus_method('write_registers', start_address, values, unit_id=self._unit_id)
            return result and not result.isError()
        except Exception as e:
            self.logger.error(f"Error writing multiple registers: {e}")
            return False
        finally:
            self.disconnect()
    
    def read_device_info(self) -> Optional[Dict[str, Any]]:
        """Read device information"""
        if not self.connect():
            return None
        
        try:
            # Try to read device ID using Report Slave ID function
            result = self._call_modbus_method('read_holding_registers', 0, count=1, unit_id=self._unit_id)
            if result and not result.isError():
                return {
                    'unit_id': self._unit_id,
                    'status': 'online',
                    'registers_accessible': True,
                    'device_type': self._device_type,
                    'address': self._ip,
                    'port': self._port
                }
            return None
        except Exception as e:
            self.logger.error(f"Error reading device info: {e}")
            return None
        finally:
            self.disconnect()
    
    def test_connection(self) -> bool:
        """Test connection to the Modbus device"""
        if not self.connect():
            return False
        
        try:
            # Try to read a single register
            result = self._call_modbus_method('read_holding_registers', 0, count=1, unit_id=self._unit_id)
            return result and not result.isError()
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
        finally:
            self.disconnect()
    
    def get_target_info(self) -> Tuple[str, str, str, str, str, str]:
        """
        Get target device information
        
        Returns:
            Tuple of (device_type, unit_id, status, registers_accessible, address, port)
        """
        try:
            info = self.read_device_info()
            if info:
                return (
                    info.get('device_type', 'Unknown'),
                    str(info.get('unit_id', 'Unknown')),
                    info.get('status', 'Unknown'),
                    str(info.get('registers_accessible', False)),
                    info.get('address', 'Unknown'),
                    str(info.get('port', 'Unknown'))
                )
            else:
                return ('Unknown', 'Unknown', 'Unknown', 'False', self._ip, str(self._port))
            
        except Exception as e:
            self.logger.error(f"Error getting target info: {e}")
            return ('Unknown', 'Unknown', 'Unknown', 'False', self._ip, str(self._port))
    
    def enumerate_device(self) -> Dict[str, List[Tuple[int, Any]]]:
        """
        Enumerate device registers
        
        Returns:
            Dictionary mapping register types to lists of (address, value) tuples
        """
        result = {}
        
        # Try to read different register types
        register_types = [
            ('coils', self.read_coils),
            ('discrete_inputs', self.read_discrete_inputs),
            ('holding_registers', self.read_holding_registers),
            ('input_registers', self.read_input_registers)
        ]
        
        for reg_type, read_func in register_types:
            found_registers = []
            
            # Try to read first 10 registers of each type
            for start_addr in range(0, 10):
                try:
                    if reg_type in ['coils', 'discrete_inputs']:
                        values = read_func(start_addr, 1)
                        if values and len(values) > 0:
                            found_registers.append((start_addr, values[0]))
                    else:
                        values = read_func(start_addr, 1)
                        if values and len(values) > 0:
                            found_registers.append((start_addr, values[0]))
                except:
                    continue
            
            if found_registers:
                result[reg_type] = found_registers
        
        return result
    
    def check_permissions(self) -> Dict[str, bool]:
        """
        Check read/write permissions for different register types
        
        Returns:
            Dictionary mapping register types to read/write permission status
        """
        permissions = {}
        
        # Test read permissions
        read_tests = [
            ('coils_read', lambda: self.read_coils(0, 1)),
            ('discrete_inputs_read', lambda: self.read_discrete_inputs(0, 1)),
            ('holding_registers_read', lambda: self.read_holding_registers(0, 1)),
            ('input_registers_read', lambda: self.read_input_registers(0, 1))
        ]
        
        for perm_name, test_func in read_tests:
            try:
                result = test_func()
                permissions[perm_name] = result is not None
            except Exception as e:
                permissions[perm_name] = False
        
        # Test write permissions (be careful!)
        write_tests = [
            ('coils_write', lambda: self.write_single_coil(0, False)),
            ('holding_registers_write', lambda: self.write_single_register(0, 0))
        ]
        
        for perm_name, test_func in write_tests:
            try:
                result = test_func()
                permissions[perm_name] = result
            except Exception as e:
                permissions[perm_name] = False
        
        return permissions

    def _call_modbus_method(self, method_name: str, *args, unit_id: int = 1, **kwargs):
        """Call pymodbus method with version-compatible parameters"""
        if not self._client:
            return None
            
        try:
            # Try with unit_id parameter (newer versions)
            if method_name == 'read_coils':
                return self._client.read_coils(*args, unit_id=unit_id, **kwargs)
            elif method_name == 'read_discrete_inputs':
                return self._client.read_discrete_inputs(*args, unit_id=unit_id, **kwargs)
            elif method_name == 'read_holding_registers':
                return self._client.read_holding_registers(*args, unit_id=unit_id, **kwargs)
            elif method_name == 'read_input_registers':
                return self._client.read_input_registers(*args, unit_id=unit_id, **kwargs)
            elif method_name == 'write_coil':
                return self._client.write_coil(*args, unit_id=unit_id, **kwargs)
            elif method_name == 'write_register':
                return self._client.write_register(*args, unit_id=unit_id, **kwargs)
            elif method_name == 'write_coils':
                return self._client.write_coils(*args, unit_id=unit_id, **kwargs)
            elif method_name == 'write_registers':
                return self._client.write_registers(*args, unit_id=unit_id, **kwargs)
        except TypeError:
            # Try with slave parameter (older versions)
            try:
                if method_name == 'read_coils':
                    return self._client.read_coils(*args, slave=unit_id, **kwargs)
                elif method_name == 'read_discrete_inputs':
                    return self._client.read_discrete_inputs(*args, slave=unit_id, **kwargs)
                elif method_name == 'read_holding_registers':
                    return self._client.read_holding_registers(*args, slave=unit_id, **kwargs)
                elif method_name == 'read_input_registers':
                    return self._client.read_input_registers(*args, slave=unit_id, **kwargs)
                elif method_name == 'write_coil':
                    return self._client.write_coil(*args, slave=unit_id, **kwargs)
                elif method_name == 'write_register':
                    return self._client.write_register(*args, slave=unit_id, **kwargs)
                elif method_name == 'write_coils':
                    return self._client.write_coils(*args, slave=unit_id, **kwargs)
                elif method_name == 'write_registers':
                    return self._client.write_registers(*args, slave=unit_id, **kwargs)
            except TypeError:
                # Try without any unit_id/slave parameter (some versions)
                if method_name == 'read_coils':
                    return self._client.read_coils(*args, **kwargs)
                elif method_name == 'read_discrete_inputs':
                    return self._client.read_discrete_inputs(*args, **kwargs)
                elif method_name == 'read_holding_registers':
                    return self._client.read_holding_registers(*args, **kwargs)
                elif method_name == 'read_input_registers':
                    return self._client.read_input_registers(*args, **kwargs)
                elif method_name == 'write_coil':
                    return self._client.write_coil(*args, **kwargs)
                elif method_name == 'write_register':
                    return self._client.write_register(*args, **kwargs)
                elif method_name == 'write_coils':
                    return self._client.write_coils(*args, **kwargs)
                elif method_name == 'write_registers':
                    return self._client.write_registers(*args, **kwargs)
        return None 