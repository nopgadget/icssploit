# CC-Link Client

## Overview

The CC-Link client is designed to interact with CC-Link IE Field Basic devices. This client is based on the [Zeek parser for CC-Link IE Field Basic](https://github.com/nttcom/zeek-parser-CCLinkFieldBasic/) and provides a comprehensive interface for communicating with CC-Link devices.

## Features

- **Connection Management**: Connect and disconnect from CC-Link devices
- **Cyclic Data Operations**: Read and write cyclic data to/from devices
- **Station Management**: Get station status and network information
- **Device Discovery**: Discover CC-Link devices on the network
- **Error Handling**: Comprehensive error handling and logging
- **Protocol Support**: Full support for CC-Link IE Field Basic protocol

## Usage

### Basic Usage

```python
from src.modules.clients.cclink_client import CCLinkClient, CCLinkStationType

# Create a CC-Link client
client = CCLinkClient(
    name="my_cclink",
    target="192.168.1.100",
    port=61450,
    station_number=1,
    station_type=CCLinkStationType.MASTER
)

# Connect to the device
if client.connect():
    print("Connected successfully!")
    
    # Read cyclic data
    data = client.read_cyclic_data(start_address=0, count=10)
    if data:
        print(f"Read data: {data}")
    
    # Write cyclic data
    success = client.write_cyclic_data(start_address=0, values=[1, 2, 3, 4])
    if success:
        print("Data written successfully!")
    
    # Get station status
    status = client.get_station_status()
    if status:
        print(f"Station status: {status}")
    
    # Disconnect
    client.disconnect()
```

### Using with ICSSploit Framework

```bash
# Use the CC-Link client
use client/cclink

# Set target options
set target 192.168.1.100
set port 61450
set station_number 1
set station_type MASTER

# Connect to the device
run

# Check connection
check

# Read cyclic data
call read_cyclic_data 0 10

# Write cyclic data
call write_cyclic_data 0 [1,2,3,4]

# Get station status
call get_station_status

# Discover devices
call discover_devices 1 64
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | string | '' | Target IP address |
| `port` | int | 61450 | CC-Link port number |
| `station_number` | int | 1 | Station number |
| `station_type` | enum | MASTER | Station type (MASTER, SLAVE, INTELLIGENT) |
| `timeout` | int | 2 | Socket timeout in seconds |
| `retry_count` | int | 3 | Number of retries for failed operations |

## Station Types

- **MASTER**: Master station (default)
- **SLAVE**: Slave station
- **INTELLIGENT**: Intelligent station

## Function Codes

The client supports the following CC-Link function codes:

- `CYCLIC_DATA_REQ` (0x01): Cyclic data request
- `CYCLIC_DATA_RES` (0x02): Cyclic data response
- `TRANSIENT_REQ` (0x03): Transient request
- `TRANSIENT_RES` (0x04): Transient response
- `MASTER_STATION_PARAMETER_SETTING_REQ` (0x05): Master station parameter setting request
- `MASTER_STATION_PARAMETER_SETTING_RES` (0x06): Master station parameter setting response
- `SLAVE_STATION_PARAMETER_SETTING_REQ` (0x07): Slave station parameter setting request
- `SLAVE_STATION_PARAMETER_SETTING_RES` (0x08): Slave station parameter setting response
- `NETWORK_STATUS_REQ` (0x09): Network status request
- `NETWORK_STATUS_RES` (0x0A): Network status response
- `STATION_STATUS_REQ` (0x0B): Station status request
- `STATION_STATUS_RES` (0x0C): Station status response
- `ERROR_STATUS_REQ` (0x0D): Error status request
- `ERROR_STATUS_RES` (0x0E): Error status response

## Methods

### Connection Methods

- `connect()`: Connect to the CC-Link device
- `disconnect()`: Disconnect from the CC-Link device
- `test_connection()`: Test the connection to the device

### Data Operations

- `read_cyclic_data(start_address, count)`: Read cyclic data from the device
- `write_cyclic_data(start_address, values)`: Write cyclic data to the device

### Status and Information

- `get_station_status()`: Get station status information
- `get_network_status()`: Get network status information
- `get_target_info()`: Get target information
- `check_permissions()`: Check device permissions

### Discovery

- `discover_devices(start_station, end_station)`: Discover CC-Link devices on the network

### Utility Methods

- `send_packet(packet)`: Send a raw packet to the device
- `receive_packet(timeout)`: Receive a packet from the device
- `send_receive_packet(packet, timeout)`: Send a packet and receive response

## Error Handling

The client includes comprehensive error handling:

- Connection errors are logged and handled gracefully
- Timeout errors are handled with configurable timeouts
- Protocol errors are logged with detailed information
- Network errors are handled with retry mechanisms

## Logging

The client uses the standard ICSSploit logging system:

```python
# Enable debug logging
client.logger.setLevel(logging.DEBUG)

# Log messages are automatically generated for:
# - Connection events
# - Data operations
# - Error conditions
# - Status changes
```

## Examples

### Example 1: Basic Data Reading

```python
client = CCLinkClient(target="192.168.1.100")
if client.connect():
    # Read 10 words starting from address 0
    data = client.read_cyclic_data(0, 10)
    if data:
        print(f"Read {len(data)} words: {data}")
    client.disconnect()
```

### Example 2: Data Writing

```python
client = CCLinkClient(target="192.168.1.100")
if client.connect():
    # Write values to addresses 0-3
    values = [100, 200, 300, 400]
    if client.write_cyclic_data(0, values):
        print("Data written successfully!")
    client.disconnect()
```

### Example 3: Device Discovery

```python
client = CCLinkClient(target="192.168.1.100")
devices = client.discover_devices(1, 64)
print(f"Discovered {len(devices)} devices:")
for device in devices:
    print(f"  Station {device.station_number}: {device.station_type.name}")
```

### Example 4: Status Monitoring

```python
client = CCLinkClient(target="192.168.1.100")
if client.connect():
    # Get station status
    status = client.get_station_status()
    if status:
        print(f"Station {status['station_number']}: {status['status']}")
    
    # Get network status
    network = client.get_network_status()
    if network:
        print(f"Network: {network['active_stations']}/{network['total_stations']} stations active")
    
    client.disconnect()
```

## Troubleshooting

### Common Issues

1. **Connection Failed**: Check if the target IP and port are correct
2. **Timeout Errors**: Increase the timeout value for slow networks
3. **Permission Denied**: Check if the device allows the requested operations
4. **Protocol Errors**: Verify that the device supports the requested function codes

### Debug Mode

Enable debug logging to get more detailed information:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## References

- [CC-Link IE Field Basic Specification](https://www.cc-link.org/en/)
- [Zeek Parser for CC-Link IE Field Basic](https://github.com/nttcom/zeek-parser-CCLinkFieldBasic/)
- [ICSSploit Framework Documentation](https://github.com/nopgadget/icssploit)
