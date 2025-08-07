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
from src.modules.clients.base import Base

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
    
    # Client options (similar to module options)
    options = ['target', 'port', 'unit_id', 'device_type', 'timeout', 'serial_port', 'baud_rate', 'data_bits', 'stop_bits', 'parity']
    
    def __init__(self, name: str, target: str = '', port: int = 502, unit_id: int = 1,
                 device_type: str = "TCP", timeout: int = 2,
                 serial_port: str = None, baud_rate: int = 9600,
                 data_bits: int = 8, stop_bits: int = 1, parity: str = "N"):
        """
        Initialize Modbus client
        
        Args:
            name: Name of this target
            target: Target Modbus device IP (for TCP) or serial port (for RTU)
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
        self._target = target
        self._port = port
        self._unit_id = unit_id
        self._device_type = device_type.upper()
        self._timeout = timeout
        self._serial_port = serial_port
        self._baud_rate = baud_rate
        self._data_bits = data_bits
        self._stop_bits = stop_bits
        self._parity = parity
        
        # Initialize client connection
        self._client = None
        self._connected = False
        
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
    def unit_id(self):
        """Get unit ID"""
        return self._unit_id
        
    @unit_id.setter
    def unit_id(self, value):
        """Set unit ID"""
        self._unit_id = int(value)
        
    @property
    def device_type(self):
        """Get device type"""
        return self._device_type
        
    @device_type.setter
    def device_type(self, value):
        """Set device type"""
        self._device_type = value.upper()
        
    @property
    def timeout(self):
        """Get timeout value"""
        return self._timeout
        
    @timeout.setter
    def timeout(self, value):
        """Set timeout value"""
        self._timeout = int(value)
        
    @property
    def serial_port(self):
        """Get serial port"""
        return self._serial_port
        
    @serial_port.setter
    def serial_port(self, value):
        """Set serial port"""
        self._serial_port = value
        
    @property
    def baud_rate(self):
        """Get baud rate"""
        return self._baud_rate
        
    @baud_rate.setter
    def baud_rate(self, value):
        """Set baud rate"""
        self._baud_rate = int(value)
        
    @property
    def data_bits(self):
        """Get data bits"""
        return self._data_bits
        
    @data_bits.setter
    def data_bits(self, value):
        """Set data bits"""
        self._data_bits = int(value)
        
    @property
    def stop_bits(self):
        """Get stop bits"""
        return self._stop_bits
        
    @stop_bits.setter
    def stop_bits(self, value):
        """Set stop bits"""
        self._stop_bits = int(value)
        
    @property
    def parity(self):
        """Get parity"""
        return self._parity
        
    @parity.setter
    def parity(self, value):
        """Set parity"""
        self._parity = value
        
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
            self.logger.info(f"Testing connectivity to {self._target}:{self._port}...")
            
            if self._device_type == "TCP":
                # Create TCP client
                self._tcp_client = ModbusTcpClient(host=self._target, port=self._port, timeout=self._timeout)
                self._client = self._tcp_client
            else:
                # Create RTU client
                self._serial_client = ModbusSerialClient(
                    method='rtu',
                    port=self._serial_port or self._target,
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
                            self.logger.info(f"Successfully connected to Modbus device at {self._target}:{self._port}")
                            return True
                        else:
                            self.logger.warning(f"Connected to {self._target}:{self._port} but device may not be responding")
                            return True  # Still consider connected, but with warning
                    except Exception as e:
                        self.logger.error(f"Connected to {self._target}:{self._port} but communication failed: {e}")
                        self._connected = False
                        return False
                else:
                    self.logger.error(f"Failed to connect to Modbus device at {self._target}:{self._port} - port may be closed")
                    return False
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Modbus device: {e}")
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
                            address=self._target,
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
    
    def write_multiple_coils(self, start_address: Union[int, str], values: Union[List[bool], List[int], str]) -> bool:
        """
        Write multiple coils (0x0F)
        
        Args:
            start_address: Starting address for writing coils (int or str like "start_address=3")
            values: List of values or comma-separated string of values. Accepts:
                   - 0/1: "0,1,0,1" or [0,1,0,1]
                   - true/false: "true,false,true" or [True,False,True]
                   - True/False: "True,False,True" or [True,False,True]
                   Can also be passed as "values=1,0,1,1"
        """
        # Handle start_address if it's a string
        if isinstance(start_address, str):
            if '=' in start_address:
                _, addr = start_address.split('=')
                start_address = int(addr)
        if not self.connect():
            return False
        
        try:
            # Convert string input to list if needed
            if isinstance(values, str):
                self.logger.debug(f"Input values (string): '{values}'")
                try:
                    # Extract values from the string
                    if values.startswith('values='):
                        values = values[7:]
                        self.logger.debug(f"After removing prefix: '{values}'")
                    
                    # Split by comma and convert to booleans
                    value_list = []
                    # Handle both comma-separated and space-separated values
                    parts = values.replace(',', ' ').split()
                    
                    for v in parts:
                        v = v.strip().lower()
                        if not v:  # Skip empty values
                            continue
                        if v in ('0', '1'):
                            value_list.append(bool(int(v)))
                        elif v in ('true', 'false'):
                            value_list.append(v == 'true')
                        else:
                            self.logger.error(f"Invalid value '{v}'. Please use 0/1 or true/false")
                            return False
                    
                    self.logger.debug(f"Parsed values: {value_list}")
                except ValueError:
                    self.logger.error("Invalid format. Examples: '1,0,1' or 'true,false,true'")
                    return False
            else:
                # Handle list input
                value_list = []
                for v in values:
                    if isinstance(v, bool):
                        value_list.append(v)
                    elif isinstance(v, (int, float)):
                        if v in (0, 1):
                            value_list.append(bool(v))
                        else:
                            self.logger.error(f"Invalid value {v}. Values must be 0 or 1")
                            return False
                    elif isinstance(v, str):
                        v = v.strip().lower()
                        if v in ('0', '1'):
                            value_list.append(bool(int(v)))
                        elif v in ('true', 'false'):
                            value_list.append(v == 'true')
                        else:
                            self.logger.error(f"Invalid value '{v}'. Please use 0/1 or true/false")
                            return False
                    else:
                        self.logger.error(f"Invalid value type {type(v)}. Values must be boolean or integer")
                        return False

            self.logger.debug(f"Final value list: {value_list}")
            result = self._call_modbus_method('write_coils', start_address, value_list, unit_id=self._unit_id)
            return result and not result.isError()
        except Exception as e:
            self.logger.error(f"Error writing multiple coils: {e}")
            return False
        finally:
            self.disconnect()
    
    def write_multiple_registers(self, start_address: Union[int, str], values: Union[List[int], str]) -> bool:
        """
        Write multiple registers (0x10)
        
        Args:
            start_address: Starting address for writing registers (int or str like "start_address=3")
            values: List of values or comma-separated string of values (e.g., "1,2,3,4" or "values=1,2,3,4")
        """
        # Handle start_address if it's a string
        if isinstance(start_address, str):
            if '=' in start_address:
                _, addr = start_address.split('=')
                start_address = int(addr)
        if not self.connect():
            return False
        
        try:
            # Convert string input to list if needed
            if isinstance(values, str):
                self.logger.debug(f"Input values (string): '{values}'")
                try:
                    # Extract values from the string
                    if values.startswith('values='):
                        values = values[7:]
                        self.logger.debug(f"After removing prefix: '{values}'")
                    
                    # Split by comma and convert to integers
                    value_list = []
                    # Handle both comma-separated and space-separated values
                    parts = values.replace(',', ' ').split()
                    
                    for v in parts:
                        v = v.strip()
                        if not v:  # Skip empty values
                            continue
                        try:
                            value_list.append(int(v))
                        except ValueError:
                            self.logger.error(f"Invalid value '{v}'. Please use integers only")
                            return False
                    
                    self.logger.debug(f"Parsed values: {value_list}")
                except ValueError:
                    self.logger.error("Invalid format. Example: '1,2,3,4'")
                    return False
            else:
                # Convert all values to integers
                try:
                    value_list = [int(v) for v in values]
                except (ValueError, TypeError):
                    self.logger.error("Invalid values. All values must be integers")
                    return False

            result = self._call_modbus_method('write_registers', start_address, value_list, unit_id=self._unit_id)
            return result and not result.isError()
        except Exception as e:
            self.logger.error(f"Error writing multiple registers: {e}")
            return False
        finally:
            self.disconnect()
    
    def read_device_info(self) -> Optional[Dict[str, Any]]:
        """
        Read comprehensive device information using various Modbus functions.
        This includes device identification, diagnostic information, and communication statistics.
        """
        if not self.connect():
            return None

        info = {
            'basic_info': {
                'unit_id': self._unit_id,
                'status': 'unknown',
                'device_type': self._device_type,
                'address': self._target,
                'port': self._port,
                'vendor': 'unknown',
                'product_code': 'unknown',
                'revision': 'unknown',
                'vendor_url': 'unknown',
                'product_name': 'unknown',
                'model_name': 'unknown',
                'user_app_name': 'unknown'
            },
            'capabilities': {
                'functions_supported': [],
                'registers_accessible': False,
                'max_registers': 0,
                'max_discrete': 0
            },
            'diagnostics': {
                'bus_message_count': 0,
                'bus_error_count': 0,
                'slave_message_count': 0,
                'slave_no_response_count': 0,
                'last_error': None,
                'running_time': 0
            },
            'comm_status': {
                'listen_only_mode': False,
                'restart_count': 0,
                'last_restart_time': None
            }
        }

        try:
            # Test basic connectivity
            result = self._call_modbus_method('read_holding_registers', 0, count=1, unit_id=self._unit_id)
            if result and not result.isError():
                info['basic_info']['status'] = 'online'
                info['capabilities']['registers_accessible'] = True

            # Try to read device identification (MEI Type 0x0E)
            try:
                result = self._call_modbus_method('report_slave_id', unit_id=self._unit_id)
                if result and not result.isError():
                    if hasattr(result, 'identifier'):
                        info['basic_info']['product_code'] = result.identifier.hex()
                    if hasattr(result, 'status'):
                        info['basic_info']['status'] = 'running' if result.status else 'stopped'
            except:
                pass

            # Try to read diagnostic information (0x08)
            diagnostic_subs = {
                0: 'Return Query Data',
                1: 'Restart Communications Option',
                2: 'Return Diagnostic Register',
                3: 'Change ASCII Input Delimiter',
                4: 'Force Listen Only Mode',
                10: 'Clear Counters and Diagnostic Register',
                11: 'Return Bus Message Count',
                12: 'Return Bus Communication Error Count',
                13: 'Return Bus Exception Error Count',
                14: 'Return Slave Message Count',
                15: 'Return Slave No Response Count'
            }

            for sub_func, name in diagnostic_subs.items():
                try:
                    result = self._call_modbus_method('diagnostic', sub_function=sub_func, unit_id=self._unit_id)
                    if result and not result.isError():
                        info['capabilities']['functions_supported'].append(name)
                        
                        # Store specific diagnostic data
                        if sub_func == 11:  # Bus Message Count
                            info['diagnostics']['bus_message_count'] = result.message_count
                        elif sub_func == 12:  # Bus Error Count
                            info['diagnostics']['bus_error_count'] = result.error_count
                        elif sub_func == 14:  # Slave Message Count
                            info['diagnostics']['slave_message_count'] = result.message_count
                        elif sub_func == 15:  # Slave No Response Count
                            info['diagnostics']['slave_no_response_count'] = result.no_response_count
                except:
                    continue

            # Test register ranges to determine maximum supported registers
            test_ranges = [50, 100, 125]
            for count in test_ranges:
                try:
                    result = self._call_modbus_method('read_holding_registers', 0, count=count, unit_id=self._unit_id)
                    if result and not result.isError():
                        info['capabilities']['max_registers'] = count
                except:
                    break

            # Format the output nicely
            self._format_device_info(info)
            # Return None to prevent showing raw dictionary in output
            return None

        except Exception as e:
            self.logger.error(f"Error reading device info: {e}")
            return None
        finally:
            self.disconnect()

    def _format_device_info(self, info: Dict[str, Any]) -> None:
        """Format device information as a readable table"""
        if not info:
            self.logger.info("No device information available")
            return

        def create_table_row(label: str, value: Any, width: int = 20) -> str:
            return f"| {label.ljust(25)} | {str(value).ljust(30)} |"

        def create_table_header(title: str) -> str:
            header = f"\n{title}\n"
            header += "+" + "-" * 27 + "+" + "-" * 32 + "+\n"
            header += "| Parameter".ljust(28) + "| Value".ljust(33) + "|\n"
            header += "+" + "-" * 27 + "+" + "-" * 32 + "+"
            return header

        def create_table_footer() -> str:
            return "+" + "-" * 27 + "+" + "-" * 32 + "+"

        # Basic Information Table
        output = create_table_header("DEVICE INFORMATION")
        basic_info = [
            ("Status", info['basic_info']['status']),
            ("Device Type", info['basic_info']['device_type']),
            ("Address", f"{info['basic_info']['address']}:{info['basic_info']['port']}"),
            ("Unit ID", info['basic_info']['unit_id']),
            ("Product Code", info['basic_info']['product_code']),
            ("Vendor", info['basic_info']['vendor'])
        ]
        for label, value in basic_info:
            output += f"\n{create_table_row(label, value)}"
        output += f"\n{create_table_footer()}"

        # Capabilities Table
        output += create_table_header("\nCAPABILITIES")
        capabilities = [
            ("Registers Accessible", info['capabilities']['registers_accessible']),
            ("Max Registers", info['capabilities']['max_registers'])
        ]
        for label, value in capabilities:
            output += f"\n{create_table_row(label, value)}"
        
        if info['capabilities']['functions_supported']:
            output += f"\n{create_table_row('Supported Functions', '')}"
            for func in info['capabilities']['functions_supported']:
                output += f"\n{create_table_row('', f'• {func}')}"
        output += f"\n{create_table_footer()}"

        # Diagnostics Table
        output += create_table_header("\nDIAGNOSTICS")
        diagnostics = [
            ("Bus Messages", info['diagnostics']['bus_message_count']),
            ("Bus Errors", info['diagnostics']['bus_error_count']),
            ("Slave Messages", info['diagnostics']['slave_message_count']),
            ("No Response Count", info['diagnostics']['slave_no_response_count'])
        ]
        for label, value in diagnostics:
            output += f"\n{create_table_row(label, value)}"
        output += f"\n{create_table_footer()}"

        # Communication Status Table
        output += create_table_header("\nCOMMUNICATION STATUS")
        comm_status = [
            ("Listen Only Mode", info['comm_status']['listen_only_mode']),
            ("Restart Count", info['comm_status']['restart_count'])
        ]
        for label, value in comm_status:
            output += f"\n{create_table_row(label, value)}"
        output += f"\n{create_table_footer()}\n"

        self.logger.info(output)
    
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
                return ('Unknown', 'Unknown', 'Unknown', 'False', self._target, str(self._port))
            
        except Exception as e:
            self.logger.error(f"Error getting target info: {e}")
            return ('Unknown', 'Unknown', 'Unknown', 'False', self._target, str(self._port))
    
    def _format_registers_table(self, registers: List[Dict[str, Any]], reg_type: str) -> str:
        """
        Format registers as a human-readable table
        """
        if not registers:
            return ""  # Return empty string for no registers
            
        # Define column widths
        widths = {
            'Address': 8,
            'Value': 8,
            'Access': 6,
            'Type': 10
        }
        
        # Create header
        header = f"{reg_type.upper()}:\n"
        header += f"{'Address'.ljust(widths['Address'])} | "
        header += f"{'Value'.ljust(widths['Value'])} | "
        header += f"{'Access'.ljust(widths['Access'])} | "
        header += f"{'Type'.ljust(widths['Type'])}\n"
        
        # Add separator line
        separator = "-" * (sum(widths.values()) + 9)  # 9 is for the " | " separators
        header += separator + "\n"
        
        # Format each register
        rows = []
        for reg in registers:
            addr = str(reg['address']).ljust(widths['Address'])
            val = str(reg['value']).ljust(widths['Value'])
            access = reg['access'].ljust(widths['Access'])
            dtype = reg['data_type'].ljust(widths['Type'])
            row = f"{addr} | {val} | {access} | {dtype}"
            rows.append(row)
        
        return header + "\n".join(rows)

    def enumerate_device(self, max_registers: int = 100, batch_size: int = 10) -> Dict[str, List[Dict[str, Any]]]:
        """
        Enumerate device registers with detailed information
        
        Args:
            max_registers: Maximum number of registers to scan per type (default: 100)
            batch_size: Number of registers to read in each batch (default: 10)
            
        Returns:
            Dictionary mapping register types to lists of register information dictionaries
            Each register info contains:
                - address: Register address or address range
                - value: Current value
                - access: Read/Write access type
                - data_type: Inferred data type (for holding/input registers)
                - description: Additional information if available
                
            Consecutive registers with the same properties are combined into ranges
            for more concise output.
        """
        result = {}
        
        # Try to read different register types
        register_types = [
            ('coils', self.read_coils, 'bit', True),  # name, read_func, data_type, writable
            ('discrete_inputs', self.read_discrete_inputs, 'bit', False),
            ('holding_registers', self.read_holding_registers, 'word', True),
            ('input_registers', self.read_input_registers, 'word', False)
        ]
        
        # Check if we're already connected
        was_connected = self._connected
        if not was_connected and not self.connect():
            return result
            
        try:
            for reg_type, read_func, data_type, writable in register_types:
                found_registers = []
                self.logger.info(f"Scanning {reg_type}...")
                
                # Scan registers in batches
                for start_addr in range(0, max_registers, batch_size):
                    try:
                        # Try to read a batch of registers
                        values = read_func(start_addr, min(batch_size, max_registers - start_addr))
                        
                        if values:
                            # Process each register in the batch
                            for offset, value in enumerate(values):
                                addr = start_addr + offset
                                
                                # Create register info dictionary
                                reg_info = {
                                    'address': addr,
                                    'value': value,
                                    'access': 'RW' if writable else 'RO',
                                    'data_type': data_type
                                }
                                
                                # Try to infer more specific data type for word registers
                                if data_type == 'word' and isinstance(value, int):
                                    if value in (0, 1):
                                        reg_info['data_type'] = 'boolean'
                                    elif -32768 <= value <= 32767:
                                        reg_info['data_type'] = 'int16'
                                    elif 0 <= value <= 65535:
                                        reg_info['data_type'] = 'uint16'
                                
                                found_registers.append(reg_info)
                                
                    except Exception as e:
                        # Log error but continue scanning
                        self.logger.debug(f"Error reading {reg_type} at address {start_addr}: {e}")
                        continue
                    
                if found_registers:
                    result[reg_type] = found_registers
            
            # Sort register types in standard order
            ordered_result = {}
            
            # Build complete table output
            table_output = "\n"  # Start with a newline for clean separation
            for reg_type in ['coils', 'discrete_inputs', 'holding_registers', 'input_registers']:
                if reg_type in result:
                    ordered_result[reg_type] = result[reg_type]
                    # Add table for this register type
                    table = self._format_registers_table(result[reg_type], reg_type)
                    if table:  # Only add if there are registers
                        table_output += table + "\n"
            
            # Log the complete table
            if table_output.strip():  # Only log if there's actual content
                self.logger.info(table_output)
            else:
                self.logger.info("No accessible registers found")
            
            # Return None to prevent the interpreter from showing the raw dictionary
            return None
            
        except Exception as e:
            self.logger.error(f"Error during device enumeration: {e}")
            return result
            
        finally:
            # Only disconnect if we weren't connected before
            if not was_connected:
                self.disconnect()
    
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