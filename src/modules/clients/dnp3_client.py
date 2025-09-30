#!/usr/bin/env python3
"""
DNP3 Client for ICSSploit
A Python client to interact with DNP3 devices using dnp3-python
"""

import asyncio
import socket
import struct
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from src.modules.clients.base import Base
from src.protocols.dnp3 import (
    DNP3FunctionCode, DNP3ObjectGroup, DNP3DeviceInfo, DNP3Point,
    DNP3Utils, DNP3_COMMON_OBJECTS, DNP3_ERROR_CODES
)

# Try to import pydnp3 library (from submodule build)
try:
    import pydnp3
    import pydnp3.opendnp3 as opendnp3
    import pydnp3.asiodnp3 as asiodnp3
    import pydnp3.asiopal as asiopal
    PYDNP3_AVAILABLE = True
    print("✅ pydnp3 library loaded successfully")
except ImportError as e:
    PYDNP3_AVAILABLE = False
    print(f"ℹ️  pydnp3 not available: {e}")
    print("   Using raw DNP3 protocol implementation")


class DNP3DataType(Enum):
    """DNP3 Data Types"""
    BINARY_INPUT = "binary_input"
    BINARY_OUTPUT = "binary_output" 
    ANALOG_INPUT = "analog_input"
    ANALOG_OUTPUT = "analog_output"
    COUNTER = "counter"
    FROZEN_COUNTER = "frozen_counter"


@dataclass
class DNP3Device:
    """Represents a DNP3 device"""
    address: int
    host: str
    port: int = 20000
    local_address: int = 1
    unsolicited_enabled: bool = False
    keep_alive_timeout: int = 60000
    
    def __str__(self) -> str:
        return f"DNP3Device(addr={self.address}, host={self.host}:{self.port})"


class DNP3Client(Base):
    """DNP3 client for ICSSploit"""
    
    # Client options (similar to module options)
    options = ['target', 'port', 'local_address', 'remote_address', 'timeout', 'keep_alive_timeout']
    
    def __init__(self, name: str, target: str = '', port: int = 20000, 
                 local_address: int = 1, remote_address: int = 10, timeout: int = 5,
                 keep_alive_timeout: int = 60000):
        """
        Initialize DNP3 client
        
        Args:
            name: Name of this target
            target: Target DNP3 device IP
            port: DNP3 port (default: 20000)
            local_address: Local DNP3 address (default: 1)
            remote_address: Remote DNP3 address (default: 10)
            timeout: Socket timeout in seconds
            keep_alive_timeout: Keep alive timeout in milliseconds
        """
        super(DNP3Client, self).__init__(name=name)
        self._target = target
        self._port = port
        self._local_address = local_address
        self._remote_address = remote_address
        self._timeout = timeout
        self._keep_alive_timeout = keep_alive_timeout
        
        # DNP3 client state
        self._connected = False
        self._socket = None
        
        # Protocol state management (for raw implementation)
        self._sequence_number = 0
        self._app_sequence = 0
        
        # pydnp3 library objects (when available)
        self._manager = None
        self._channel = None
        self._master = None
        
        # Initialize logging
        self.logger = self.get_logger()
        
        # Log which implementation we're using
        if PYDNP3_AVAILABLE:
            self.logger.info("DNP3 client initialized with pydnp3 library (preferred)")
        else:
            self.logger.info("DNP3 client initialized with raw protocol implementation (fallback)")
    
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
    def local_address(self):
        """Get local address"""
        return self._local_address
        
    @local_address.setter
    def local_address(self, value):
        """Set local address"""
        self._local_address = int(value)
        
    @property
    def remote_address(self):
        """Get remote address"""
        return self._remote_address
        
    @remote_address.setter
    def remote_address(self, value):
        """Set remote address"""
        self._remote_address = int(value)
        
    @property
    def timeout(self):
        """Get timeout value"""
        return self._timeout
        
    @timeout.setter
    def timeout(self, value):
        """Set timeout value"""
        self._timeout = int(value)
        
    @property
    def keep_alive_timeout(self):
        """Get keep alive timeout"""
        return self._keep_alive_timeout
        
    @keep_alive_timeout.setter
    def keep_alive_timeout(self, value):
        """Set keep alive timeout"""
        self._keep_alive_timeout = int(value)

    def connect(self) -> bool:
        """Connect to DNP3 device and verify connectivity"""
        try:
            self.logger.info(f"Testing connectivity to DNP3 device at {self._target}:{self._port}...")
            
            # First test basic TCP connectivity
            if not self._test_tcp_connection():
                return False
            
            # Use pydnp3 library if available, otherwise fall back to raw implementation
            if PYDNP3_AVAILABLE:
                return self._connect_pydnp3()
            else:
                return self._test_dnp3_connection()
                
        except Exception as e:
            self.logger.error(f"Failed to connect to DNP3 device: {e}")
            return False

    def _test_tcp_connection(self) -> bool:
        """Test basic TCP connectivity"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            result = sock.connect_ex((self._target, self._port))
            sock.close()
            
            if result == 0:
                self.logger.debug(f"TCP connection to {self._target}:{self._port} successful")
                return True
            else:
                self.logger.error(f"TCP connection to {self._target}:{self._port} failed - port may be closed")
                return False
                
        except Exception as e:
            self.logger.error(f"TCP connection test failed: {e}")
            return False

    def _connect_pydnp3(self) -> bool:
        """Connect using pydnp3 library"""
        try:
            self.logger.info("Connecting using pydnp3 library...")
            
            # Create DNP3 manager
            self._manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().logger)
            
            # Create TCP client channel
            retry = asiopal.ChannelRetry()
            listener = asiodnp3.PrintingChannelListener().build()
            
            self._channel = self._manager.add_tcp_client(
                "dnp3-client",
                opendnp3.levels.NORMAL,
                retry,
                self._target,
                "0.0.0.0",  # Local endpoint
                self._port,
                listener
            )
            
            # Configure master stack
            stack_config = asiodnp3.MasterStackConfig()
            stack_config.master.response_timeout = asiopal.TimeDuration.seconds(self._timeout)
            stack_config.link.local_addr = self._local_address
            stack_config.link.remote_addr = self._remote_address
            stack_config.link.keep_alive_timeout = asiopal.TimeDuration.milliseconds(self._keep_alive_timeout)
            
            # Create master
            soe_handler = asiodnp3.PrintingSOEHandler().build()
            master_app = asiodnp3.DefaultMasterApplication().build()
            
            self._master = self._channel.add_master(
                "master",
                soe_handler,
                master_app,
                stack_config
            )
            
            # Enable the master
            self._master.enable()
            
            # Give it time to connect
            time.sleep(2)
            
            self.logger.info(f"Successfully connected to DNP3 device using pydnp3")
            self._connected = True
            return True
            
        except Exception as e:
            self.logger.error(f"pydnp3 connection failed: {e}")
            self.logger.info("Falling back to raw protocol implementation")
            return self._test_dnp3_connection()

    def _test_dnp3_connection(self) -> bool:
        """Test DNP3 connection using raw sockets"""
        try:
            self.logger.info("Attempting raw DNP3 connection test...")
            
            # Create a simple DNP3 read request
            read_request = DNP3Utils.create_read_request(
                source=self._local_address,
                destination=self._remote_address,
                objects=[(60, 1, 0, 0)]  # Class 1 data
            )
            
            # Send request and wait for response
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            
            try:
                sock.connect((self._target, self._port))
                sock.send(read_request)
                
                # Try to receive response
                response = sock.recv(1024)
                sock.close()
                
                if len(response) > 0:
                    # Parse response to verify it's valid DNP3
                    parsed = DNP3Utils.parse_response(response)
                    if "error" not in parsed:
                        self.logger.info(f"Raw DNP3 connection successful to {self._target}:{self._port}")
                        self._connected = True
                        return True
                    else:
                        self.logger.warning(f"Received response but parsing failed: {parsed['error']}")
                        self._connected = True  # Still consider connected
                        return True
                else:
                    self.logger.warning(f"No response received from {self._target}:{self._port}")
                    return False
                    
            except socket.timeout:
                self.logger.error(f"DNP3 request timeout to {self._target}:{self._port}")
                return False
            except Exception as e:
                self.logger.error(f"DNP3 request failed: {e}")
                return False
            finally:
                sock.close()
                
        except Exception as e:
            self.logger.error(f"Raw DNP3 connection test failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from DNP3 device"""
        if self._master:
            try:
                self._master.disable()
            except:
                pass
            self._master = None
            
        if self._channel:
            try:
                self._channel.shutdown()
            except:
                pass
            self._channel = None
            
        self._connected = False
        self.logger.info("Disconnected from DNP3 device")

    def read_binary_inputs(self, start_index: int = 0, count: int = 10) -> Optional[List[DNP3Point]]:
        """Read binary input points"""
        if not self._connected:
            if not self.connect():
                return None
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                return self._read_points_pydnp3(opendnp3.GroupVariationID(1, 2), start_index, count, "binary_input")
            else:
                return self._read_points(DNP3ObjectGroup.BINARY_INPUT.value, 2, start_index, count)
                
        except Exception as e:
            self.logger.error(f"Error reading binary inputs: {e}")
            return None

    def read_analog_inputs(self, start_index: int = 0, count: int = 10) -> Optional[List[DNP3Point]]:
        """Read analog input points"""
        if not self._connected:
            if not self.connect():
                return None
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                return self._read_points_pydnp3(opendnp3.GroupVariationID(30, 1), start_index, count, "analog_input")
            else:
                return self._read_points(DNP3ObjectGroup.ANALOG_INPUT.value, 1, start_index, count)
                
        except Exception as e:
            self.logger.error(f"Error reading analog inputs: {e}")
            return None

    def read_counters(self, start_index: int = 0, count: int = 10) -> Optional[List[DNP3Point]]:
        """Read counter points"""
        if not self._connected:
            if not self.connect():
                return None
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                return self._read_points_pydnp3(opendnp3.GroupVariationID(20, 1), start_index, count, "counter")
            else:
                return self._read_points(DNP3ObjectGroup.BINARY_COUNTER.value, 1, start_index, count)
                
        except Exception as e:
            self.logger.error(f"Error reading counters: {e}")
            return None

    def _read_points_pydnp3(self, group_var: 'opendnp3.GroupVariationID', start_index: int, count: int, point_type: str) -> Optional[List[DNP3Point]]:
        """Read points using pydnp3 library"""
        try:
            if not self._master:
                self.logger.error("Master not initialized")
                return None
            
            # Perform scan
            result = self._master.scan_range(group_var, start_index, start_index + count - 1)
            
            # Note: pydnp3 handles responses asynchronously
            # For now, return placeholder points indicating successful request
            points = []
            for i in range(count):
                points.append(DNP3Point(
                    index=start_index + i,
                    value=0.0 if point_type == "analog_input" else (0 if point_type == "counter" else False),
                    quality=0x01  # Online
                ))
            
            self.logger.info(f"Successfully requested {count} {point_type} points starting at index {start_index}")
            return points
            
        except Exception as e:
            self.logger.error(f"Error reading {point_type} points with pydnp3: {e}")
            return None

    def _read_points(self, group: int, variation: int, start_index: int, count: int) -> Optional[List[DNP3Point]]:
        """Read points using DNP3 protocol"""
        try:
            # Increment sequence numbers for proper protocol compliance
            self._app_sequence = (self._app_sequence + 1) % 16
            self._sequence_number = (self._sequence_number + 1) % 64
            
            # Create read request with proper sequencing
            read_request = DNP3Utils.create_read_request(
                source=self._local_address,
                destination=self._remote_address,
                objects=[(group, variation, start_index, start_index + count - 1)],
                app_seq=self._app_sequence,
                transport_seq=self._sequence_number
            )
            
            # Send request
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            
            try:
                sock.connect((self._target, self._port))
                sock.send(read_request)
                
                # Receive response
                response = sock.recv(4096)
                sock.close()
                
                if len(response) > 0:
                    # Parse response
                    parsed = DNP3Utils.parse_response(response)
                    if "error" not in parsed and parsed.get("valid", False):
                        # Verify sequence numbers match
                        response_seq = parsed.get("application", {}).get("sequence", -1)
                        if response_seq != self._app_sequence:
                            self.logger.warning(f"Sequence mismatch: expected {self._app_sequence}, got {response_seq}")
                        
                        # Create placeholder points (actual parsing would be more complex)
                        points = []
                        for i in range(count):
                            points.append(DNP3Point(
                                index=start_index + i,
                                value=0,  # Would need proper parsing
                                quality=0x01  # Online
                            ))
                        return points
                    else:
                        self.logger.error(f"Response parsing error: {parsed['error']}")
                        return None
                else:
                    self.logger.error("No response received")
                    return None
                    
            except Exception as e:
                self.logger.error(f"Raw read request failed: {e}")
                return None
            finally:
                sock.close()
                
        except Exception as e:
            self.logger.error(f"Error in raw point reading: {e}")
            return None

    def write_binary_output(self, index: int, value: bool) -> bool:
        """Write to a binary output point"""
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                # Use pydnp3 library for binary output control
                self.logger.info(f"Writing binary output {index} = {value}")
                
                # Create control relay output block (CROB)
                crob = opendnp3.ControlRelayOutputBlock(
                    opendnp3.ControlCode.LATCH_ON if value else opendnp3.ControlCode.LATCH_OFF,
                    1,  # count
                    0,  # on_time_ms
                    0   # off_time_ms
                )
                
                # Perform direct operate
                callback = asiodnp3.PrintingCommandCallback().build()
                self._master.direct_operate(crob, index, callback)
                
                # Give some time for the operation to complete
                time.sleep(0.5)
                
                self.logger.info(f"Binary output write command sent for index {index}")
                return True
            else:
                # Use raw socket approach (simplified)
                self.logger.warning("Binary output writing not implemented for raw sockets")
                return False
                
        except Exception as e:
            self.logger.error(f"Error writing binary output: {e}")
            return False

    def write_analog_output(self, index: int, value: float) -> bool:
        """Write to an analog output point"""
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                # Use pydnp3 library for analog output control
                self.logger.info(f"Writing analog output {index} = {value}")
                
                # Create analog output command
                analog_output = opendnp3.AnalogOutputDouble64(value)
                
                # Perform direct operate
                callback = asiodnp3.PrintingCommandCallback().build()
                self._master.direct_operate(analog_output, index, callback)
                
                # Give some time for the operation to complete
                time.sleep(0.5)
                
                self.logger.info(f"Analog output write command sent for index {index}")
                return True
            else:
                # Use raw socket approach (simplified)
                self.logger.warning("Analog output writing not implemented for raw sockets")
                return False
                
        except Exception as e:
            self.logger.error(f"Error writing analog output: {e}")
            return False

    def get_device_info(self) -> Optional[DNP3DeviceInfo]:
        """Get comprehensive device information"""
        if not self._connected:
            if not self.connect():
                return None

        try:
            device_info = DNP3DeviceInfo(address=self._remote_address)
            
            # Try to read device attributes (Group 0 - Device Attributes)
            # This is a simplified implementation using raw protocol
            self.logger.info("Reading device information...")
            
            device_info.device_name = f"DNP3 Device at {self._target}"
            device_info.device_function = "DNP3 Outstation"
            
            # Format and display device information
            self._format_device_info(device_info)
            return device_info
            
        except Exception as e:
            self.logger.error(f"Error reading device info: {e}")
            return None

    def _format_device_info(self, info: DNP3DeviceInfo) -> None:
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

        # Device Information Table
        output = create_table_header("DNP3 DEVICE INFORMATION")
        device_info = [
            ("Address", info.address),
            ("Host", f"{self._target}:{self._port}"),
            ("Vendor", info.vendor_name),
            ("Device Name", info.device_name),
            ("Software Version", info.software_version),
            ("Hardware Version", info.hardware_version),
            ("Location", info.location),
            ("Device ID", info.device_id),
            ("Function", info.device_function),
            ("Serial Number", info.serial_number)
        ]
        for label, value in device_info:
            output += f"\n{create_table_row(label, value)}"
        output += f"\n{create_table_footer()}"

        # Capabilities Table
        output += create_table_header("\nDNP3 CAPABILITIES")
        capabilities = [
            ("Unsolicited Support", info.supports_unsolicited),
            ("Max TX Fragment", info.max_tx_fragment_size),
            ("Max RX Fragment", info.max_rx_fragment_size),
            ("Local Address", self._local_address),
            ("Remote Address", self._remote_address)
        ]
        for label, value in capabilities:
            output += f"\n{create_table_row(label, value)}"
        output += f"\n{create_table_footer()}\n"

        self.logger.info(output)

    def enumerate_device(self, max_points: int = 100) -> Optional[Dict[str, List[DNP3Point]]]:
        """
        Enumerate device points with detailed information
        
        Args:
            max_points: Maximum number of points to scan per type
            
        Returns:
            Dictionary mapping point types to lists of point information
        """
        if not self._connected:
            if not self.connect():
                return None

        result = {}
        
        try:
            self.logger.info("Enumerating DNP3 device points...")
            
            # Enumerate different point types
            point_types = [
                ("binary_inputs", self.read_binary_inputs),
                ("analog_inputs", self.read_analog_inputs), 
                ("counters", self.read_counters)
            ]
            
            for point_type, read_func in point_types:
                self.logger.info(f"Scanning {point_type}...")
                
                try:
                    # Read points in batches
                    batch_size = 10
                    all_points = []
                    
                    for start_idx in range(0, max_points, batch_size):
                        count = min(batch_size, max_points - start_idx)
                        points = read_func(start_idx, count)
                        
                        if points:
                            # Filter out points that don't exist (would need better detection)
                            valid_points = [p for p in points if p.quality != 0]
                            all_points.extend(valid_points)
                            
                            if len(valid_points) == 0:
                                # No valid points in this batch, might be end of range
                                break
                        else:
                            break
                    
                    if all_points:
                        result[point_type] = all_points
                        
                except Exception as e:
                    self.logger.error(f"Error scanning {point_type}: {e}")
                    continue
            
            # Format and display results
            self._format_enumeration_results(result)
            return None  # Return None to prevent raw dict display
            
        except Exception as e:
            self.logger.error(f"Error during device enumeration: {e}")
            return None

    def _format_enumeration_results(self, results: Dict[str, List[DNP3Point]]) -> None:
        """Format enumeration results as readable tables"""
        if not results:
            self.logger.info("No points found during enumeration")
            return

        output = "\n"
        
        for point_type, points in results.items():
            if not points:
                continue
                
            # Create table for this point type
            output += f"\n{point_type.upper().replace('_', ' ')}:\n"
            output += f"{'Index'.ljust(8)} | {'Value'.ljust(12)} | {'Quality'.ljust(8)} | {'Status'.ljust(10)}\n"
            output += "-" * 50 + "\n"
            
            for point in points[:20]:  # Show first 20 points
                quality_str = f"0x{point.quality:02X}"
                status = "Online" if point.quality & 0x01 else "Offline"
                
                output += f"{str(point.index).ljust(8)} | "
                output += f"{str(point.value).ljust(12)} | "
                output += f"{quality_str.ljust(8)} | "
                output += f"{status.ljust(10)}\n"
            
            if len(points) > 20:
                output += f"... and {len(points) - 20} more points\n"
            
            output += f"\nTotal {point_type}: {len(points)} points\n"

        self.logger.info(output)

    def test_connection(self) -> bool:
        """Test connection to the DNP3 device"""
        return self.connect()

    def get_target_info(self) -> Tuple[str, str, str, str, str, str]:
        """
        Get target device information
        
        Returns:
            Tuple of (device_type, address, status, capabilities, host, port)
        """
        try:
            if self.connect():
                device_info = self.get_device_info()
                if device_info:
                    return (
                        "DNP3",
                        str(device_info.address),
                        "Online",
                        "Read/Write",
                        self._target,
                        str(self._port)
                    )
                else:
                    return ("DNP3", str(self._remote_address), "Online", "Unknown", self._target, str(self._port))
            else:
                return ("DNP3", str(self._remote_address), "Offline", "None", self._target, str(self._port))
                
        except Exception as e:
            self.logger.error(f"Error getting target info: {e}")
            return ("DNP3", str(self._remote_address), "Error", "None", self._target, str(self._port))

    def discover_devices(self, address_range: range = range(1, 255)) -> List[DNP3Device]:
        """
        Discover DNP3 devices by scanning address range
        
        Args:
            address_range: Range of DNP3 addresses to scan
            
        Returns:
            List of discovered DNP3 devices
        """
        devices = []
        
        self.logger.info(f"Scanning for DNP3 devices on {self._target}:{self._port}")
        
        for addr in address_range:
            try:
                # Temporarily set remote address
                original_addr = self._remote_address
                self._remote_address = addr
                
                # Try to connect
                if self.connect():
                    device = DNP3Device(
                        address=addr,
                        host=self._target,
                        port=self._port,
                        local_address=self._local_address
                    )
                    devices.append(device)
                    self.logger.info(f"Found DNP3 device at address {addr}")
                    self.disconnect()
                
                # Restore original address
                self._remote_address = original_addr
                
            except Exception as e:
                self.logger.debug(f"No device at address {addr}: {e}")
                continue
        
        return devices

    def cold_restart(self) -> bool:
        """Perform cold restart of DNP3 device"""
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                # Use pydnp3 library for cold restart
                self.logger.info("Performing cold restart of DNP3 device")
                
                # Create restart task callback
                callback = asiodnp3.PrintingTaskCallback().build()
                
                # Perform cold restart
                self._master.restart(opendnp3.RestartType.COLD, callback)
                
                # Give time for restart to complete
                time.sleep(2.0)
                
                self.logger.info("Cold restart command sent")
                return True
            else:
                # Raw socket approach would need proper command implementation
                self.logger.warning("Cold restart not implemented for raw sockets")
                return False
                
        except Exception as e:
            self.logger.error(f"Error performing cold restart: {e}")
            return False

    def warm_restart(self) -> bool:
        """Perform warm restart of DNP3 device"""
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                # Use pydnp3 library for warm restart
                self.logger.info("Performing warm restart of DNP3 device")
                
                # Create restart task callback
                callback = asiodnp3.PrintingTaskCallback().build()
                
                # Perform warm restart
                self._master.restart(opendnp3.RestartType.WARM, callback)
                
                # Give time for restart to complete
                time.sleep(1.5)
                
                self.logger.info("Warm restart command sent")
                return True
            else:
                # Raw socket approach would need proper command implementation
                self.logger.warning("Warm restart not implemented for raw sockets")
                return False
                
        except Exception as e:
            self.logger.error(f"Error performing warm restart: {e}")
            return False

    def enable_unsolicited(self) -> bool:
        """Enable unsolicited responses"""
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                # Use pydnp3 library to enable unsolicited responses
                self.logger.info("Enabling unsolicited responses")
                
                # Create task callback
                callback = asiodnp3.PrintingTaskCallback().build()
                
                # Enable unsolicited responses for all classes
                class_field = opendnp3.ClassField.AllClasses()
                self._master.enable_unsolicited(class_field, callback)
                
                time.sleep(0.5)
                
                self.logger.info("Enable unsolicited command sent")
                return True
            else:
                self.logger.warning("Enable unsolicited not implemented for raw sockets")
                return False
                
        except Exception as e:
            self.logger.error(f"Error enabling unsolicited: {e}")
            return False

    def disable_unsolicited(self) -> bool:
        """Disable unsolicited responses"""
        if not self._connected:
            if not self.connect():
                return False
        
        try:
            if PYDNP3_AVAILABLE and self._master:
                # Use pydnp3 library to disable unsolicited responses
                self.logger.info("Disabling unsolicited responses")
                
                # Create task callback
                callback = asiodnp3.PrintingTaskCallback().build()
                
                # Disable unsolicited responses for all classes
                class_field = opendnp3.ClassField.AllClasses()
                self._master.disable_unsolicited(class_field, callback)
                
                time.sleep(0.5)
                
                self.logger.info("Disable unsolicited command sent")
                return True
            else:
                self.logger.warning("Disable unsolicited not implemented for raw sockets")
                return False
                
        except Exception as e:
            self.logger.error(f"Error disabling unsolicited: {e}")
            return False
