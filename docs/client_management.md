# Client Management in ICSSploit

ICSSploit now includes a comprehensive client management system that allows you to create, manage, and interact with various industrial protocol clients directly from the command line interface.

## Overview

The client management system provides a unified interface for working with different industrial protocol clients including:

- **BACnet** - Building Automation and Control Networks
- **Modbus** - Industrial communication protocol
- **Modbus TCP** - Modbus over TCP/IP
- **S7** - Siemens S7 protocol
- **S7 Plus** - Enhanced S7 protocol
- **OPC UA** - OPC Unified Architecture
- **CIP** - Common Industrial Protocol
- **WDB2** - Wind River Debug Protocol

## Available Commands

### Basic Client Management

```bash
# List available client types
client types

# Create a new client
client create <type> <name> [options]

# List all created clients
client list

# Set current client
client use <name>

# Get client information
client info <name>

# Remove a client
client remove <name>
```

### Connection Management

```bash
# Connect to a client
client connect <name>

# Disconnect from a client
client disconnect <name>
```

### Client Interaction

```bash
# Call client methods directly
client call <name> <method> [args...]

# Get help for a specific client type
client help <type>
```

## Usage Examples

### BACnet Client

```bash
# Create a BACnet client (uses default port 47808)
client create bacnet my_bacnet ip=192.168.1.100

# Or specify a custom port
client create bacnet my_bacnet ip=192.168.1.100 port=47809

# Connect to the device
client connect my_bacnet

# Discover devices on the network
client call my_bacnet discover_devices

# Read a property
client call my_bacnet read_property "device,1" "objectName"

# Write a property
client call my_bacnet write_property "analogOutput,1" "presentValue" 75.5
```

### Modbus Client

```bash
# Create a Modbus client (uses default port 502)
client create modbus my_modbus ip=192.168.1.101

# Or specify a custom port
client create modbus my_modbus ip=192.168.1.101 port=503

# Connect to the device
client connect my_modbus

# Read holding registers
client call my_modbus read_holding_registers 0 10

# Write to a register
client call my_modbus write_single_register 0 1234
```

### S7 Client

```bash
# Create an S7 client (uses default port 102)
client create s7 my_s7 ip=192.168.1.102

# Or specify a custom port
client create s7 my_s7 ip=192.168.1.102 port=103

# Connect to the PLC
client connect my_s7

# Read data blocks
client call my_s7 read_area "DB" 1 0 10

# Write to data blocks
client call my_s7 write_area "DB" 1 0 [1, 2, 3, 4]
```

## Client Options

When creating clients, you can specify various options depending on the client type:

### Common Options
- `ip=<ip_address>` - Target IP address
- `port=<port_number>` - Target port number (if not specified, default port is used)
- `timeout=<seconds>` - Connection timeout
- `device_id=<id>` - Device identifier (for some protocols)

### Default Ports

If you don't specify a port when creating a client, the system will automatically use the default port for that protocol:

- **BACnet**: 47808
- **Modbus**: 502
- **S7**: 102
- **OPC UA**: 4840
- **CIP**: 44818
- **WDB2**: 17185

Example:
```bash
# This will use the default BACnet port (47808)
client create bacnet my_bacnet ip=192.168.1.100

# This will use the specified port
client create bacnet my_bacnet ip=192.168.1.100 port=47809
```

### BACnet Specific
- `device_id=<id>` - Local device ID (default: 999)

### Modbus Specific
- `unit_id=<id>` - Unit identifier (default: 1)

### S7 Specific
- `rack=<rack>` - Rack number
- `slot=<slot>` - Slot number

## Tab Completion

The client system includes intelligent tab completion:

- `client <TAB>` - Shows available sub-commands
- `client create <TAB>` - Shows available client types
- `client use <TAB>` - Shows available client names
- `client call <name> <TAB>` - Shows available methods for the client

## Error Handling

The client management system includes comprehensive error handling:

- Invalid client types are rejected with clear error messages
- Connection failures are reported with detailed information
- Method calls that fail are reported with error details
- Missing clients or methods are clearly identified

## Integration with Modules

Clients can be used in conjunction with ICSSploit modules:

1. Create and configure a client
2. Use the client to gather information about a target
3. Use that information to configure modules for exploitation
4. Use the client to verify successful exploitation

## Best Practices

1. **Naming**: Use descriptive names for clients (e.g., `plc_floor1`, `hmi_main`)
2. **Connection Management**: Always disconnect clients when done
3. **Error Handling**: Check return values from client method calls
4. **Documentation**: Use `client help <type>` to understand available methods
5. **Cleanup**: Remove unused clients to free resources

## Troubleshooting

### Common Issues

1. **Connection Failed**: Check IP address, port, and network connectivity
2. **Method Not Found**: Use `client help <type>` to see available methods
3. **Client Not Found**: Use `client list` to see available clients
4. **Permission Denied**: Some operations may require specific permissions

### Debug Information

Enable debug logging to see detailed client operations:

```bash
# Set debug level (if supported by your logging configuration)
set LOG_LEVEL DEBUG
```

## Advanced Usage

### Scripting with Clients

You can use clients programmatically in custom scripts:

```python
from icssploit.client_manager import ClientManager

# Create client manager
cm = ClientManager()

# Create a client
client = cm.create_client('bacnet', 'test_client', ip='192.168.1.100')

# Use the client
if client:
    client.connect()
    devices = client.discover_devices()
    print(f"Found {len(devices)} devices")
```

### Custom Client Extensions

You can extend the client system by adding new client types to the `ClientManager.available_clients` dictionary in `icssploit/client_manager.py`.

## Complete Usage Example

Here's a complete example of how to use the client functionality in ICSSploit:

```bash
# Start ICSSploit
python3 icssploit.py

# 1. List available client types
client types

# 2. Create a BACnet client (uses default port 47808)
client create bacnet my_bacnet_client ip=192.168.1.100

# 3. Create a Modbus client (uses default port 502)
client create modbus my_modbus_client ip=192.168.1.101

# 4. List all created clients
client list

# 5. Connect to a client
client connect my_bacnet_client

# 6. Set current client
client use my_bacnet_client

# 7. Get client information
client info my_bacnet_client

# 8. Call client methods directly
client call my_bacnet_client discover_devices
client call my_bacnet_client read_property "device,1" "objectName"

# 9. Disconnect client
client disconnect my_bacnet_client

# 10. Remove client
client remove my_bacnet_client

# 11. Get help for a specific client type
client help bacnet
```

### Step-by-Step Workflow

1. **Start ICSSploit**: Run `python3 icssploit.py`
2. **Explore Available Clients**: Use `client types` to see what protocols are supported
3. **Create Clients**: Use `client create <type> <name> [options]` to create client instances
4. **Connect**: Use `client connect <name>` to establish connections
5. **Interact**: Use `client call <name> <method> [args]` to interact with devices
6. **Clean Up**: Use `client disconnect <name>` and `client remove <name>` when done

### Common Use Cases

**Device Discovery:**
```bash
client create bacnet scanner ip=192.168.1.100
client connect scanner
client call scanner discover_devices
```

**Property Reading:**
```bash
client create bacnet reader ip=192.168.1.100
client connect reader
client call reader read_property "device,1" "objectName"
client call reader read_property "analogInput,1" "presentValue"
```

**Register Operations:**
```bash
client create modbus plc ip=192.168.1.101
client connect plc
client call plc read_holding_registers 0 10
client call plc write_single_register 0 1234
```

**PLC Communication:**
```bash
client create s7 siemens ip=192.168.1.102
client connect siemens
client call siemens read_area "DB" 1 0 10
client call siemens write_area "DB" 1 0 [1, 2, 3, 4]
``` 