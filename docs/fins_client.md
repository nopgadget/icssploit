# FINS Client

## Overview

The FINS (Factory Interface Network Service) client is designed to interact with Omron FINS devices. This client is based on the FINS protocol specification and provides a comprehensive interface for communicating with Omron industrial devices in control systems.

## Features

- **Connection Management**: Connect and disconnect from FINS devices with handshake protocol
- **Memory Operations**: Read and write to various memory areas (CIO, DM, HR, AR, etc.)
- **CPU Control**: Start and stop CPU execution
- **Status Monitoring**: Get CPU unit status and device information
- **Clock Operations**: Read and write device clock
- **Device Discovery**: Discover FINS devices on the network
- **Error Handling**: Comprehensive error handling and logging
- **Protocol Support**: Full support for Omron FINS protocol

## Testing

For testing the FINS client, you can use:

1. **Omron PLC Simulator**: Use Omron's official PLC simulator software
2. **Real Omron Device**: Connect to a physical Omron PLC or device
3. **Network Scanner**: Use tools like Nmap to discover FINS devices

## Basic Python Usage

### Creating a FINS Client

```python
from src.modules.clients.fins_client import FINSClient, FINSMemoryArea

# Create a basic FINS client
client = FINSClient(
    name="test_fins",
    target="192.168.1.100",
    port=9600,
    node_address=0,
    timeout=2,
    retry_count=3
)
```

### Connecting to a Device

```python
# Connect to the FINS device
if client.connect():
    print("Successfully connected to FINS device")
else:
    print("Failed to connect to FINS device")
```

### Reading Memory Areas

```python
# Read from Data Memory (DM) area
values = client.read_memory_area(FINSMemoryArea.DM, start_address=0, count=10)
if values:
    print(f"Read {len(values)} values from DM area: {values}")

# Read from CIO (Common I/O) area
cio_values = client.read_memory_area(FINSMemoryArea.CIO, start_address=0, count=5)
if cio_values:
    print(f"Read {len(cio_values)} values from CIO area: {cio_values}")

# Read from Holding Area (HR)
hr_values = client.read_memory_area(FINSMemoryArea.HR, start_address=0, count=5)
if hr_values:
    print(f"Read {len(hr_values)} values from HR area: {hr_values}")
```

### Writing to Memory Areas

```python
# Write to Data Memory (DM) area
values_to_write = [100, 200, 300, 400, 500]
success = client.write_memory_area(FINSMemoryArea.DM, start_address=0, values=values_to_write)
if success:
    print("Successfully wrote values to DM area")
else:
    print("Failed to write values to DM area")
```

### CPU Control

```python
# Get CPU unit status
status = client.get_cpu_unit_status()
if status:
    print(f"CPU Status: {status}")
    print(f"Run Mode: {status.get('run_mode', 'Unknown')}")
    print(f"CPU Unit Status: {status.get('cpu_unit_status', 'Unknown')}")

# Start CPU execution
if client.run_cpu():
    print("CPU started successfully")
else:
    print("Failed to start CPU")

# Stop CPU execution
if client.stop_cpu():
    print("CPU stopped successfully")
else:
    print("Failed to stop CPU")
```

### Getting Device Information

```python
# Get device clock
clock = client.get_clock()
if clock:
    print(f"Device Clock: {clock['year']}-{clock['month']:02d}-{clock['day']:02d} "
          f"{clock['hour']:02d}:{clock['minute']:02d}:{clock['second']:02d}")

# Get target information
target_info = client.get_target_info()
print(f"Target: {target_info[0]}:{target_info[1]}")
print(f"Node Address: {target_info[2]}")
print(f"Status: {target_info[3]}")
print(f"Version: {target_info[4]}")
print(f"Description: {target_info[5]}")
```

### Discovering Devices

```python
# Discover FINS devices on the network
devices = client.discover_devices("192.168.1.0/24")
for device in devices:
    print(f"Found device: {device.ip_address} (Node: {device.node_address})")
```

### Disconnecting

```python
# Disconnect from the device
client.disconnect()
```

## Integration with ICSSploit Framework

### Using the Client Manager

```python
from src.client_manager import ClientManager

# Create client manager
manager = ClientManager()

# Load FINS client
manager.use_client('fins', name='my_fins', target='192.168.1.100')

# Get current client
client = manager.get_current_client()

# Connect to device
if manager.connect_client('my_fins'):
    print("Connected successfully")
    
    # Read memory
    values = client.read_memory_area(FINSMemoryArea.DM, 0, 5)
    if values:
        print(f"Memory values: {values}")
    
    # Get status
    status = client.get_cpu_unit_status()
    if status:
        print(f"CPU Status: {status}")
    
    # Disconnect
    manager.disconnect_client('my_fins')
```

### Command Line Interface

```bash
# Load FINS client
use_client fins my_fins target=192.168.1.100

# Connect to device
connect_client my_fins

# Read memory area
execute_client_method my_fins read_memory_area DM 0 10

# Get CPU status
execute_client_method my_fins get_cpu_unit_status

# Start CPU
execute_client_method my_fins run_cpu

# Stop CPU
execute_client_method my_fins stop_cpu

# Get device clock
execute_client_method my_fins get_clock

# Discover devices
execute_client_method my_fins discover_devices "192.168.1.0/24"

# Disconnect
disconnect_client my_fins
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | str | '' | Target FINS device IP address |
| `port` | int | 9600 | FINS port number |
| `node_address` | int | 0 | FINS node address |
| `timeout` | int | 2 | Socket timeout in seconds |
| `retry_count` | int | 3 | Number of retries for failed operations |

## Supported Commands

### FINS Command Codes

- `MEMORY_AREA_READ` (0x0101): Read from memory area
- `MEMORY_AREA_WRITE` (0x0102): Write to memory area
- `MEMORY_AREA_FILL` (0x0103): Fill memory area
- `MULTIPLE_MEMORY_AREA_READ` (0x0104): Read from multiple memory areas
- `MEMORY_AREA_TRANSFER` (0x0105): Transfer between memory areas
- `PARAMETER_AREA_READ` (0x0201): Read from parameter area
- `PARAMETER_AREA_WRITE` (0x0202): Write to parameter area
- `PROGRAM_AREA_READ` (0x0301): Read from program area
- `PROGRAM_AREA_WRITE` (0x0302): Write to program area
- `CPU_UNIT_DATA_READ` (0x0401): Read CPU unit data
- `CPU_UNIT_DATA_WRITE` (0x0402): Write CPU unit data
- `CPU_UNIT_STATUS_READ` (0x0501): Read CPU unit status
- `CPU_UNIT_STATUS_WRITE` (0x0502): Write CPU unit status
- `RUN` (0x0401): Start CPU execution
- `STOP` (0x0402): Stop CPU execution
- `CLOCK_READ` (0x0701): Read device clock
- `CLOCK_WRITE` (0x0702): Write device clock
- `MESSAGE` (0x0801): Send message
- `ACCESS_RIGHT_REQUEST` (0x0C01): Request access rights
- `ACCESS_RIGHT_RELEASE` (0x0C02): Release access rights
- `ERROR_LOG_READ` (0x0D01): Read error log
- `ERROR_LOG_CLEAR` (0x0D02): Clear error log
- `FINS_NODE_ADDRESS_READ` (0x0E01): Read FINS node address
- `FINS_NODE_ADDRESS_WRITE` (0x0E02): Write FINS node address
- `NETWORK_STATUS_READ` (0x0F01): Read network status
- `REMOTE_NODE_STATUS_READ` (0x0F02): Read remote node status
- `CONTROLLER_DATA_READ` (0x1001): Read controller data
- `CONTROLLER_DATA_WRITE` (0x1002): Write controller data
- `CONNECTION_DATA_READ` (0x1101): Read connection data
- `CONNECTION_DATA_WRITE` (0x1102): Write connection data

### FINS Memory Areas

- `CIO` (0xB0): CIO (Common I/O)
- `WR` (0xB1): Work Area
- `HR` (0xB2): Holding Area
- `AR` (0xB3): Auxiliary Area
- `DM` (0x82): Data Memory
- `EM` (0xA0): Extended Data Memory
- `TIM` (0x89): Timer Area
- `CNT` (0x89): Counter Area
- `TASK` (0x04): Task Area

### FINS Response Codes

- `NORMAL_COMPLETION` (0x0000): Operation successful
- `LOCAL_NODE_NOT_IN_NETWORK` (0x0001): Local node not in network
- `DESTINATION_NODE_NOT_IN_NETWORK` (0x0002): Destination node not in network
- `COMMUNICATIONS_UNIT_ERROR` (0x0003): Communications unit error
- `DESTINATION_NODE_DUPLICATE_FINS_ADDRESS` (0x0004): Duplicate FINS address
- `TOO_MANY_SEND_FRAMES` (0x0005): Too many send frames
- `NODE_NUMBER_RANGE_ERROR` (0x0006): Node number range error
- `DESTINATION_NODE_FINS_MESSAGE_OVERFLOW` (0x0007): Message overflow
- `FORMAT_ERROR` (0x0008): Format error
- `NOT_RECEIVABLE` (0x0009): Not receivable
- `DESTINATION_NODE_WATCHDOG_TIMER_ERROR` (0x000A): Watchdog timer error
- `DESTINATION_NODE_FINS_BUFFER_OVERFLOW` (0x000B): Buffer overflow
- `DESTINATION_NODE_FINS_BUFFER_FULL` (0x000C): Buffer full
- `DESTINATION_NODE_FINS_MESSAGE_LENGTH_ERROR` (0x000D): Message length error
- `DESTINATION_NODE_FINS_COMMAND_FORMAT_ERROR` (0x000E): Command format error
- `DESTINATION_NODE_FINS_COMMAND_NOT_SUPPORTED` (0x000F): Command not supported
- `DESTINATION_NODE_FINS_COMMAND_PROCESSING_ERROR` (0x0010): Command processing error
- `DESTINATION_NODE_FINS_COMMAND_EXECUTION_ERROR` (0x0011): Command execution error
- `DESTINATION_NODE_FINS_COMMAND_EXECUTION_TIMEOUT` (0x0012): Command execution timeout
- `DESTINATION_NODE_FINS_COMMAND_EXECUTION_ABORTED` (0x0013): Command execution aborted
- `DESTINATION_NODE_FINS_COMMAND_EXECUTION_DISABLED` (0x0014): Command execution disabled
- `DESTINATION_NODE_FINS_COMMAND_EXECUTION_NOT_READY` (0x0015): Command execution not ready
- `DESTINATION_NODE_FINS_COMMAND_EXECUTION_BUSY` (0x0016): Command execution busy

## Methods

### Connection Management

- `connect()`: Connect to FINS device and establish handshake
- `disconnect()`: Disconnect from FINS device
- `test_connection()`: Test connection to FINS device

### Memory Operations

- `read_memory_area(memory_area, start_address, count)`: Read from memory area
- `write_memory_area(memory_area, start_address, values)`: Write to memory area

### CPU Control

- `run_cpu()`: Start CPU execution
- `stop_cpu()`: Stop CPU execution
- `get_cpu_unit_status()`: Get CPU unit status

### Device Information

- `get_clock()`: Get device clock
- `get_target_info()`: Get target information

### Data Communication

- `send_packet(packet)`: Send raw packet
- `receive_packet(timeout)`: Receive packet
- `send_receive_packet(packet, timeout)`: Send packet and receive response

### Device Discovery

- `discover_devices(network_range)`: Discover FINS devices on the network

### Utility Methods

- `check_permissions()`: Check device permissions
- `_send_fins_handshake()`: Send FINS handshake
- `_create_fins_header(command_code, data_length)`: Create FINS packet header
- `_increment_sequence()`: Increment sequence number

## Error Handling

The FINS client includes comprehensive error handling:

- **Connection Errors**: Automatic retry with configurable retry count
- **Handshake Errors**: Proper handling of FINS handshake failures
- **Protocol Errors**: Proper handling of FINS response codes
- **Network Errors**: Timeout handling and connection state management

## Logging

The client uses the ICSSploit logging system:

```python
# Enable debug logging
client.logger.setLevel(logging.DEBUG)

# Log messages include:
# - Connection status
# - Handshake process
# - Memory operations
# - CPU control operations
# - Error conditions
```

## Examples

### Complete Example

```python
from src.modules.clients.fins_client import FINSClient, FINSMemoryArea
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

# Create client
client = FINSClient(
    name="test_fins",
    target="192.168.1.100",
    port=9600,
    node_address=0,
    timeout=2
)

try:
    # Connect to device
    if client.connect():
        print("Connected to FINS device")
        
        # Get CPU status
        status = client.get_cpu_unit_status()
        if status:
            print(f"CPU Status: {status}")
        
        # Read memory area
        values = client.read_memory_area(FINSMemoryArea.DM, 0, 5)
        if values:
            print(f"Memory values: {values}")
        
        # Write to memory area
        test_values = [100, 200, 300, 400, 500]
        if client.write_memory_area(FINSMemoryArea.DM, 0, test_values):
            print("Successfully wrote to memory")
        
        # Get device clock
        clock = client.get_clock()
        if clock:
            print(f"Device Clock: {clock}")
        
        # Test connection
        if client.test_connection():
            print("Connection test successful")
        
        # Check permissions
        permissions = client.check_permissions()
        print(f"Permissions: {permissions}")
        
    else:
        print("Failed to connect to FINS device")
        
finally:
    # Always disconnect
    client.disconnect()
    print("Disconnected from FINS device")
```

### Memory Operations Example

```python
from src.modules.clients.fins_client import FINSClient, FINSMemoryArea

# Create client
client = FINSClient(name="memory_test", target="192.168.1.100")

if client.connect():
    # Read from different memory areas
    memory_areas = [
        (FINSMemoryArea.DM, "Data Memory"),
        (FINSMemoryArea.CIO, "CIO"),
        (FINSMemoryArea.HR, "Holding Area"),
        (FINSMemoryArea.AR, "Auxiliary Area")
    ]
    
    for area, name in memory_areas:
        values = client.read_memory_area(area, 0, 5)
        if values:
            print(f"{name}: {values}")
        else:
            print(f"Failed to read {name}")
    
    client.disconnect()
```

### CPU Control Example

```python
from src.modules.clients.fins_client import FINSClient

# Create client
client = FINSClient(name="cpu_control", target="192.168.1.100")

if client.connect():
    # Get current status
    status = client.get_cpu_unit_status()
    if status:
        print(f"Current CPU Status: {status}")
    
    # Stop CPU
    if client.stop_cpu():
        print("CPU stopped")
    
    # Wait a moment
    import time
    time.sleep(2)
    
    # Start CPU
    if client.run_cpu():
        print("CPU started")
    
    client.disconnect()
```

## Troubleshooting

### Common Issues

1. **Connection Failed**
   - Check if the target IP is correct
   - Verify the port is open (default: 9600)
   - Ensure the device supports FINS protocol

2. **Handshake Failed**
   - Check if the device is already at maximum connections
   - Verify network connectivity
   - Check device status

3. **Memory Read/Write Failed**
   - Check if the memory area exists
   - Verify the address range is valid
   - Check device permissions

4. **CPU Control Failed**
   - Check if the device supports CPU control
   - Verify device is in the correct mode
   - Check device status

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

client = FINSClient(name="debug", target="192.168.1.100")
# Debug information will be logged
```

## References

- [Omron FINS Protocol Specification](https://www.omron.com/global/en/solutions/automation/network/)
- [Wireshark FINS Dissector](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-omron-fins.c)
- [Redpoint FINS NSE Script](https://github.com/digitalbond/Redpoint/blob/master/omrontcp-info.nse)
- [ICSSploit Framework Documentation](https://github.com/nopgadget/icssploit)
- [Industrial Protocol Security](https://github.com/Orange-Cyberdefense/awesome-industrial-protocols)

## License

This client is part of the ICSSploit framework and follows the same licensing terms.
