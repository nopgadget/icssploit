# DNP3 Client Documentation

## Overview

The DNP3 client module provides comprehensive support for interacting with DNP3 (IEEE 1815) devices in industrial control systems. DNP3 is a widely used protocol in SCADA systems, particularly for communication between control centers and remote terminal units (RTUs) or intelligent electronic devices (IEDs).

## Features

- **Full DNP3 Protocol Support**: Implements DNP3 data link, transport, and application layers
- **Device Discovery**: Scan networks for DNP3 devices using address enumeration
- **Point Enumeration**: Discover and read binary inputs, analog inputs, counters, and other data points
- **Device Information**: Retrieve comprehensive device information and capabilities
- **Control Operations**: Support for binary and analog output control (where supported)
- **Restart Commands**: Cold and warm restart functionality
- **Unsolicited Response Control**: Enable/disable unsolicited responses
- **Raw Protocol Support**: Fallback to raw socket implementation when dnp3-python is not available

## Installation

### Prerequisites

Install the required DNP3 library:

```bash
pip install dnp3-python
```

### Dependencies

The DNP3 client requires the following Python packages:
- `dnp3-python` - Primary DNP3 library (recommended)
- `socket` - For raw protocol implementation (fallback)
- Standard Python libraries: `struct`, `enum`, `dataclasses`, `typing`

## Usage

### Basic Client Usage

```python
from src.modules.clients.dnp3_client import DNP3Client

# Create DNP3 client
client = DNP3Client(
    name="MyDNP3Client",
    target="192.168.1.100",
    port=20000,
    local_address=1,
    remote_address=10
)

# Connect to device
if client.connect():
    print("Connected successfully!")
    
    # Get device information
    device_info = client.get_device_info()
    
    # Read binary inputs
    binary_inputs = client.read_binary_inputs(start_index=0, count=10)
    
    # Read analog inputs
    analog_inputs = client.read_analog_inputs(start_index=0, count=5)
    
    # Enumerate all device points
    all_points = client.enumerate_device(max_points=100)
    
    # Disconnect
    client.disconnect()
```

### Scanner Module Usage

Use the DNP3 scanner to discover devices on a network:

```bash
# Basic network scan
use scanners/dnp3_scan
set target 192.168.1.0/24
run

# Scan with enumeration
set enumerate true
set get_device_info true
run

# Scan specific address range
set start_address 1
set end_address 100
set port 20000
run

# Export results
export /tmp/dnp3_scan_results.csv
```

## Configuration Options

### Client Options

| Option | Default | Description |
|--------|---------|-------------|
| `target` | "" | Target DNP3 device IP address |
| `port` | 20000 | DNP3 TCP port |
| `local_address` | 1 | Local DNP3 data link address |
| `remote_address` | 10 | Remote DNP3 data link address |
| `timeout` | 5 | Connection timeout in seconds |
| `keep_alive_timeout` | 60000 | Keep-alive timeout in milliseconds |

### Scanner Options

| Option | Default | Description |
|--------|---------|-------------|
| `target` | "" | Network range to scan (nmap format) |
| `port` | 20000 | DNP3 port to scan |
| `local_address` | 1 | Local DNP3 address for scanning |
| `start_address` | 1 | Start of DNP3 address range to test |
| `end_address` | 50 | End of DNP3 address range to test |
| `enumerate` | false | Perform full point enumeration |
| `get_device_info` | true | Retrieve detailed device information |
| `timeout` | 5 | Connection timeout in seconds |

## DNP3 Protocol Details

### Supported Object Groups

The client supports reading from the following DNP3 object groups:

- **Group 1**: Binary Input (variations 1, 2)
- **Group 10**: Binary Output (variations 1, 2)
- **Group 20**: Binary Counter (variations 1, 2, 3, 4, 5, 6)
- **Group 30**: Analog Input (variations 1, 2, 3, 4, 5, 6)
- **Group 40**: Analog Output (variations 1, 2, 3, 4)
- **Group 60**: Class Data (variations 1, 2, 3, 4)

### Function Codes

Supported DNP3 function codes include:

- **READ (0x01)**: Read data from device
- **WRITE (0x02)**: Write data to device
- **DIRECT_OPERATE (0x05)**: Direct operate command
- **COLD_RESTART (0x0D)**: Cold restart device
- **WARM_RESTART (0x0E)**: Warm restart device
- **ENABLE_UNSOLICITED (0x14)**: Enable unsolicited responses
- **DISABLE_UNSOLICITED (0x15)**: Disable unsolicited responses

### Data Link Layer

The implementation handles DNP3 data link layer features:

- **Addressing**: Support for 16-bit source and destination addresses
- **CRC Checking**: Automatic CRC calculation and verification
- **Frame Formatting**: Proper DNP3 frame structure with start bytes
- **Error Detection**: Frame integrity checking

## API Reference

### DNP3Client Class

#### Connection Methods

```python
def connect() -> bool
```
Establish connection to DNP3 device. Returns True if successful.

```python
def disconnect() -> None
```
Disconnect from DNP3 device and clean up resources.

```python
def test_connection() -> bool
```
Test connectivity without maintaining connection.

#### Data Reading Methods

```python
def read_binary_inputs(start_index: int = 0, count: int = 10) -> Optional[List[DNP3Point]]
```
Read binary input points from the device.

```python
def read_analog_inputs(start_index: int = 0, count: int = 10) -> Optional[List[DNP3Point]]
```
Read analog input points from the device.

```python
def read_counters(start_index: int = 0, count: int = 10) -> Optional[List[DNP3Point]]
```
Read counter points from the device.

#### Control Methods

```python
def write_binary_output(index: int, value: bool) -> bool
```
Write to a binary output point.

```python
def write_analog_output(index: int, value: float) -> bool
```
Write to an analog output point.

#### Device Information Methods

```python
def get_device_info() -> Optional[DNP3DeviceInfo]
```
Retrieve comprehensive device information.

```python
def enumerate_device(max_points: int = 100) -> Optional[Dict[str, List[DNP3Point]]]
```
Enumerate all available points on the device.

#### Control Commands

```python
def cold_restart() -> bool
```
Perform cold restart of the device.

```python
def warm_restart() -> bool
```
Perform warm restart of the device.

```python
def enable_unsolicited() -> bool
```
Enable unsolicited responses from the device.

```python
def disable_unsolicited() -> bool
```
Disable unsolicited responses from the device.

### DNP3Point Class

Represents a DNP3 data point:

```python
@dataclass
class DNP3Point:
    index: int              # Point index/address
    value: Any              # Point value
    quality: int = 0        # Quality flags
    timestamp: Optional[int] = None  # Timestamp (if available)
```

### DNP3DeviceInfo Class

Contains device information:

```python
@dataclass
class DNP3DeviceInfo:
    address: int                    # Device DNP3 address
    vendor_name: str = "Unknown"    # Vendor name
    device_name: str = "Unknown"    # Device name
    software_version: str = "Unknown"  # Software version
    hardware_version: str = "Unknown"  # Hardware version
    location: str = "Unknown"       # Device location
    device_id: str = "Unknown"      # Device identifier
    device_function: str = "Unknown"  # Device function
    serial_number: str = "Unknown"  # Serial number
    supports_unsolicited: bool = False  # Unsolicited support
    max_tx_fragment_size: int = 2048    # Max TX fragment size
    max_rx_fragment_size: int = 2048    # Max RX fragment size
```

## Examples

### Example 1: Basic Device Scan

```python
# Scan for DNP3 devices on local network
use scanners/dnp3_scan
set target 192.168.1.0/24
set port 20000
set start_address 1
set end_address 50
run
```

### Example 2: Detailed Device Enumeration

```python
# Connect to specific device and enumerate all points
use clients/dnp3_client
set target 192.168.1.100
set port 20000
set remote_address 10
connect
enumerate_device
get_device_info
disconnect
```

### Example 3: Reading Specific Points

```python
# Read specific data points
client = DNP3Client("test", "192.168.1.100", remote_address=10)
if client.connect():
    # Read first 10 binary inputs
    binary_points = client.read_binary_inputs(0, 10)
    for point in binary_points:
        print(f"Binary Input {point.index}: {point.value}")
    
    # Read first 5 analog inputs
    analog_points = client.read_analog_inputs(0, 5)
    for point in analog_points:
        print(f"Analog Input {point.index}: {point.value}")
    
    client.disconnect()
```

### Example 4: Device Control

```python
# Control device outputs
client = DNP3Client("control", "192.168.1.100", remote_address=10)
if client.connect():
    # Write to binary output
    success = client.write_binary_output(0, True)
    print(f"Binary output write: {'Success' if success else 'Failed'}")
    
    # Write to analog output
    success = client.write_analog_output(0, 123.45)
    print(f"Analog output write: {'Success' if success else 'Failed'}")
    
    client.disconnect()
```

## Troubleshooting

### Common Issues

1. **Connection Timeout**
   - Verify target IP and port
   - Check network connectivity
   - Ensure DNP3 service is running on target
   - Try different DNP3 addresses

2. **No Devices Found**
   - Verify port number (common: 20000, 19999, 502)
   - Expand address range (start_address/end_address)
   - Check for non-standard DNP3 configurations
   - Verify network access and firewall settings

3. **Library Import Errors**
   - Install dnp3-python: `pip install dnp3-python`
   - Check Python version compatibility
   - Verify all dependencies are installed

4. **Permission Errors**
   - Some operations may require specific DNP3 security settings
   - Check device configuration for read/write permissions
   - Verify authentication requirements

### Debug Mode

Enable debug logging for detailed protocol information:

```python
client = DNP3Client("debug", "192.168.1.100")
client.set_verbosity(1)  # Enable debug logging
```

### Raw Protocol Mode

If dnp3-python is not available, the client automatically falls back to raw socket implementation:

```python
# Raw mode is automatically used when dnp3-python is not installed
# Provides basic connectivity testing and simple read operations
```

## Security Considerations

### DNP3 Security

- **Authentication**: Some DNP3 implementations support Secure Authentication
- **Encryption**: DNP3 Secure Authentication can provide encryption
- **Access Control**: Devices may have read/write permission controls
- **Audit Logging**: Monitor DNP3 communications for security events

### Best Practices

1. **Network Segmentation**: Isolate SCADA networks from corporate networks
2. **Monitoring**: Log all DNP3 communications for security analysis
3. **Access Control**: Implement proper authentication and authorization
4. **Regular Updates**: Keep DNP3 devices and software updated
5. **Testing**: Use this tool only on authorized systems

## References

- [IEEE 1815-2012 (DNP3) Standard](https://standards.ieee.org/standard/1815-2012.html)
- [DNP Users Group](https://www.dnp.org/)
- [DNP3 Protocol Primer](https://www.dnp.org/About/DNP3%20Primer%20Rev%20A.pdf)
- [OpenDNP3 Documentation](https://dnp3.github.io/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## License

This DNP3 client implementation is part of ICSSploit and follows the same licensing terms. Use responsibly and only on authorized systems.
