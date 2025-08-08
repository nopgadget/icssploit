# ENIP Client

## Overview

The ENIP (Ethernet/IP) client is designed to interact with Ethernet/IP devices. This client is based on the ENIP protocol specification and provides a comprehensive interface for communicating with Ethernet/IP devices in industrial control systems.

## Features

- **Connection Management**: Connect and disconnect from ENIP devices with session management
- **Device Discovery**: Discover ENIP devices on the network
- **Identity Information**: Get device identity, vendor, and product information
- **Service Discovery**: List services supported by the device
- **Data Communication**: Send Request/Response (RR) data and Unit data
- **Session Management**: Automatic session registration and timeout handling
- **Error Handling**: Comprehensive error handling and logging
- **Protocol Support**: Full support for Ethernet/IP protocol (ENIP)

## Testing

For testing the ENIP client, we use the **ENIP PLC Simulator** Docker container:

```bash
# Pull and run the ENIP PLC Simulator
docker pull colortokenslabs/enip-plc-simulator
docker run -d -p 44818:44818 --name enip-simulator colortokenslabs/enip-plc-simulator
```

The simulator will be available at `localhost:44818` and can be used to test all ENIP client functionality.

## Basic Python Usage

### Creating an ENIP Client

```python
from src.modules.clients.enip_client import ENIPClient

# Create a basic ENIP client
client = ENIPClient(
    name="test_enip",
    target="192.168.1.100",
    port=44818,
    timeout=2,
    session_timeout=30,
    retry_count=3
)
```

### Connecting to a Device

```python
# Connect to the ENIP device
if client.connect():
    print("Successfully connected to ENIP device")
else:
    print("Failed to connect to ENIP device")
```

### Getting Device Information

```python
# Get device identity information
identity = client.list_identity()
if identity:
    print(f"Product Name: {identity['product_name']}")
    print(f"Vendor: {identity['vendor_name']}")
    print(f"Device Type: {identity['device_type']}")
    print(f"Revision: {identity['revision']}")
    print(f"Serial Number: {identity['serial_number']}")
```

### Discovering Devices

```python
# Discover ENIP devices on the network
devices = client.discover_devices("192.168.1.0/24")
for device in devices:
    print(f"Found device: {device.product_name} at {device.ip_address}")
```

### Sending Data

```python
# Send Request/Response data
test_data = b'\x00\x00\x00\x00'  # Example data
response = client.send_rr_data(test_data)
if response:
    print(f"Received response: {response}")

# Send Unit data
success = client.send_unit_data(test_data)
if success:
    print("Unit data sent successfully")
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

# Load ENIP client
manager.use_client('enip', name='my_enip', target='192.168.1.100')

# Get current client
client = manager.get_current_client()

# Connect to device
if manager.connect_client('my_enip'):
    print("Connected successfully")
    
    # Get device identity
    identity = client.list_identity()
    if identity:
        print(f"Device: {identity['product_name']}")
    
    # Disconnect
    manager.disconnect_client('my_enip')
```

### Command Line Interface

```bash
# Load ENIP client
use_client enip my_enip target=192.168.1.100

# Connect to device
connect_client my_enip

# Get device information
execute_client_method my_enip list_identity

# Discover devices
execute_client_method my_enip discover_devices "192.168.1.0/24"

# Disconnect
disconnect_client my_enip
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | str | '' | Target ENIP device IP address |
| `port` | int | 44818 | ENIP port number |
| `timeout` | int | 2 | Socket timeout in seconds |
| `session_timeout` | int | 30 | Session timeout in seconds |
| `retry_count` | int | 3 | Number of retries for failed operations |

## Supported Commands

### ENIP Commands

- `NOP` (0x0000): No operation
- `LIST_SERVICES` (0x0004): List services
- `LIST_IDENTITY` (0x0063): List identity
- `LIST_INTERFACES` (0x0064): List interfaces
- `REGISTER_SESSION` (0x0065): Register session
- `UNREGISTER_SESSION` (0x0066): Unregister session
- `SEND_RR_DATA` (0x006f): Send Request/Response data
- `SEND_UNIT_DATA` (0x0070): Send Unit data
- `INDICATE_STATUS` (0x0072): Indicate status
- `CANCEL` (0x0073): Cancel

### ENIP Status Codes

- `SUCCESS` (0x00000000): Operation successful
- `INVALID_COMMAND` (0x00000001): Invalid command
- `INSUFFICIENT_MEMORY` (0x00000002): Insufficient memory
- `INCORRECT_DATA` (0x00000003): Incorrect data
- `INVALID_SESSION_HANDLE` (0x0064): Invalid session handle
- `INVALID_LENGTH` (0x0065): Invalid length
- `UNSUPPORTED_PROTOCOL_VERSION` (0x0069): Unsupported protocol version

## Methods

### Connection Management

- `connect()`: Connect to ENIP device and register session
- `disconnect()`: Disconnect from ENIP device and unregister session
- `test_connection()`: Test connection to ENIP device

### Device Information

- `list_identity()`: Get device identity information
- `list_services()`: Get list of services supported by the device
- `get_target_info()`: Get target information

### Data Communication

- `send_rr_data(data, timeout)`: Send Request/Response data
- `send_unit_data(data, timeout)`: Send Unit data
- `send_packet(packet)`: Send raw packet
- `receive_packet(timeout)`: Receive packet
- `send_receive_packet(packet, timeout)`: Send packet and receive response

### Device Discovery

- `discover_devices(network_range)`: Discover ENIP devices on the network

### Utility Methods

- `check_permissions()`: Check device permissions
- `_register_session()`: Register session with device
- `_unregister_session()`: Unregister session
- `_check_session_validity()`: Check if session is still valid

## Error Handling

The ENIP client includes comprehensive error handling:

- **Connection Errors**: Automatic retry with configurable retry count
- **Session Management**: Automatic session registration and timeout handling
- **Protocol Errors**: Proper handling of ENIP status codes
- **Network Errors**: Timeout handling and connection state management

## Logging

The client uses the ICSSploit logging system:

```python
# Enable debug logging
client.logger.setLevel(logging.DEBUG)

# Log messages include:
# - Connection status
# - Session management
# - Data transmission
# - Error conditions
```

## Examples

### Complete Example

```python
from src.modules.clients.enip_client import ENIPClient
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

# Create client
client = ENIPClient(
    name="test_enip",
    target="192.168.1.100",
    port=44818,
    timeout=2,
    session_timeout=30
)

try:
    # Connect to device
    if client.connect():
        print("Connected to ENIP device")
        
        # Get device identity
        identity = client.list_identity()
        if identity:
            print(f"Device: {identity['product_name']}")
            print(f"Vendor: {identity['vendor_name']}")
            print(f"Revision: {identity['revision']}")
        
        # Get services
        services = client.list_services()
        if services:
            print(f"Available services: {len(services)}")
            for service in services:
                print(f"  - {service['service_name']}")
        
        # Send test data
        test_data = b'\x00\x00\x00\x00'
        response = client.send_rr_data(test_data)
        if response:
            print(f"Received response: {response.hex()}")
        
        # Test connection
        if client.test_connection():
            print("Connection test successful")
        
        # Check permissions
        permissions = client.check_permissions()
        print(f"Permissions: {permissions}")
        
    else:
        print("Failed to connect to ENIP device")
        
finally:
    # Always disconnect
    client.disconnect()
    print("Disconnected from ENIP device")
```

### Network Discovery Example

```python
from src.modules.clients.enip_client import ENIPClient

# Create client for discovery
client = ENIPClient(name="discovery", target="192.168.1.1")

# Discover devices on network
print("Discovering ENIP devices...")
devices = client.discover_devices("192.168.1.0/24")

if devices:
    print(f"Found {len(devices)} ENIP devices:")
    for device in devices:
        print(f"  - {device.product_name} at {device.ip_address}")
        print(f"    Vendor: {device.vendor_name}")
        print(f"    Type: {device.device_type}")
        print(f"    Revision: {device.revision}")
        print(f"    Serial: {device.serial_number}")
        print()
else:
    print("No ENIP devices found")
```

## Troubleshooting

### Common Issues

1. **Connection Failed**
   - Check if the target IP is correct
   - Verify the port is open (default: 44818)
   - Ensure the device supports ENIP protocol

2. **Session Registration Failed**
   - Check if the device is already at maximum sessions
   - Verify network connectivity
   - Check device status

3. **No Response Received**
   - Increase timeout value
   - Check network connectivity
   - Verify device is responding

4. **Permission Denied**
   - Check device security settings
   - Verify user permissions
   - Check device configuration

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

client = ENIPClient(name="debug", target="192.168.1.100")
# Debug information will be logged
```

## References

- [Ethernet/IP Protocol Specification](https://www.odva.org/technology-standards/key-technologies/ethernet-ip)
- [ENIP PLC Simulator Docker Image](https://hub.docker.com/r/colortokenslabs/enip-plc-simulator)
- [ICSSploit Framework Documentation](https://github.com/nopgadget/icssploit)
- [Industrial Protocol Security](https://github.com/Orange-Cyberdefense/awesome-industrial-protocols)

## License

This client is part of the ICSSploit framework and follows the same licensing terms.
