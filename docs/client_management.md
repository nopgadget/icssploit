# Client Management in ICSSploit

ICSSploit now includes a unified client system that works exactly like modules! Clients are selected with `use client/<type>` and configured with the same commands you already know.

## Overview

The unified client system provides a module-like interface for working with different industrial protocol clients including:

- **BACnet** - Building Automation and Control Networks
- **Modbus** - Industrial communication protocol
- **Modbus TCP** - Modbus over TCP/IP
- **S7** - Siemens S7 protocol
- **S7 Plus** - Enhanced S7 protocol
- **OPC UA** - OPC Unified Architecture
- **CIP** - Common Industrial Protocol
- **WDB2** - Wind River Debug Protocol
- **ZMQ** - ZeroMQ messaging protocol

## Quick Start

### List Available Clients
```bash
show clients
```

### Use a Client (Like a Module)
```bash
use client/zmq
```

### Configure Client Options
```bash
set target 192.168.1.100
set port 5555
set timeout 10
```

### Show Current Options
```bash
options
```

### Run the Client (Connect)
```bash
run
```

### Check Connectivity
```bash
check
```

### Send/Receive Messages
```bash
send "Hello World"
receive
```

### Call Client Methods
```bash
call discover_devices
```

### Go Back to Global Context
```bash
back
```

## Available Commands

### Global Commands (Work with both modules and clients)
- `use client/<type>` - Select a client (like `use module`)
- `set <option> <value>` - Set client options (like module options)
- `options` - Show client options (like module options)
- `run` - Run the client (connect and test)
- `check` - Check connectivity
- `back` - Go back to global context

### Client-Specific Commands
- `send <message>` - Send a message to the client
- `receive` - Receive a message from the client
- `call <method> [args...]` - Call a client method directly

## Usage Examples

### ZMQ Client Example

```bash
# Use a ZMQ client
icssploit > use client/zmq
[+] Using zmq client: zmq_client

# Configure the client
icssploit (ZMQClient:zmq_client) > set target 192.168.1.100
[+] {'target': '192.168.1.100'}
icssploit (ZMQClient:zmq_client) > set port 5555
[+] {'port': '5555'}
icssploit (ZMQClient:zmq_client) > set timeout 10
[+] {'timeout': '10'}

# Show current options
icssploit (ZMQClient:zmq_client) > options
Target options:
   Name       Current settings     Description
   ----       ----------------     -----------
   target     192.168.1.100        No description available
   port       5555                 No description available

Client options:
   Name            Current settings     Description
   ----            ----------------     -----------
   socket_type     ZMQSocketType.REQ    No description available
   transport       ZMQTransport.TCP     No description available
   timeout         10                   No description available
   topic           None                 No description available

# Run the client (connect)
icssploit (ZMQClient:zmq_client) > run
[*] Running client...
[+] Connected to zmq_client

# Send a message
icssploit (ZMQClient:zmq_client) > send "PING"
[+] Message sent: True

# Receive a message
icssploit (ZMQClient:zmq_client) > receive
[+] Received: PONG

# Call a method
icssploit (ZMQClient:zmq_client) > call discover_devices
[+] Method discover_devices returned: [device1, device2]

# Go back to global context
icssploit (ZMQClient:zmq_client) > back
[+] Deselected client: zmq_client
icssploit >
```

### Modbus Client Example

```bash
# Use a Modbus client
icssploit > use client/modbus
[+] Using modbus client: modbus_client

# Configure the client
icssploit (ModbusClient:modbus_client) > set target 192.168.1.101
[+] {'target': '192.168.1.101'}
icssploit (ModbusClient:modbus_client) > set port 502
[+] {'port': '502'}

# Run the client (connect)
icssploit (ModbusClient:modbus_client) > run
[*] Running client...
[+] Connected to modbus_client

# Call client methods
icssploit (ModbusClient:modbus_client) > call read_holding_registers 0 10
[+] Method read_holding_registers returned: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

# Go back to global context
icssploit (ModbusClient:modbus_client) > back
[+] Deselected client: modbus_client
icssploit >
```

### S7 Client Example

```bash
# Use an S7 client
icssploit > use client/s7
[+] Using s7 client: s7_client

# Configure the client
icssploit (S7Client:s7_client) > set target 192.168.1.102
[+] {'target': '192.168.1.102'}
icssploit (S7Client:s7_client) > set port 102
[+] {'port': '102'}

# Run the client (connect)
icssploit (S7Client:s7_client) > run
[*] Running client...
[+] Connected to s7_client

# Call client methods
icssploit (S7Client:s7_client) > call read_area "DB" 1 0 10
[+] Method read_area returned: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

# Go back to global context
icssploit (S7Client:s7_client) > back
[+] Deselected client: s7_client
icssploit >
```

## Client Options

Each client type has specific options that can be configured:

### Common Options (All Clients)
- `target` - Target IP address
- `port` - Target port number (uses default if not specified)

### ZMQ Client Options
- `socket_type` - Socket type (REQ, REP, PUB, SUB, etc.)
- `transport` - Transport protocol (TCP, IPC, etc.)
- `timeout` - Connection timeout in seconds
- `topic` - Topic for pub/sub operations

### Modbus Client Options
- `unit_id` - Unit identifier
- `device_type` - Device type (TCP, RTU)

### S7 Client Options
- `rack` - Rack number
- `slot` - Slot number

## Default Ports

If you don't specify a port when configuring a client, the system will automatically use the default port for that protocol:

- **BACnet**: 47808
- **Modbus**: 502
- **S7**: 102
- **OPC UA**: 4840
- **CIP**: 44818
- **WDB2**: 17185
- **ZMQ**: 5555

## Tab Completion

The client system includes intelligent tab completion:

- `use client/<TAB>` - Shows available client types
- `set <TAB>` - Shows available options for the current client
- `call <TAB>` - Shows available methods for the current client
- `show <TAB>` - Shows available show sub-commands including `clients`

## Error Handling

The client system includes comprehensive error handling:

- Invalid client types are rejected with clear error messages
- Connection failures are reported with detailed information
- Method calls that fail are reported with error details
- Missing clients or methods are clearly identified

## Integration with Modules

Clients can be used in conjunction with ICSSploit modules:

1. **Information Gathering**: Use clients to discover devices and gather information
2. **Module Configuration**: Use gathered information to configure modules
3. **Exploitation**: Run modules against discovered targets
4. **Verification**: Use clients to verify successful exploitation

## Best Practices

1. **Configuration**: Always set the target before running the client
2. **Connection Management**: Use `run` to connect and test the client
3. **Error Handling**: Check return values from client method calls
4. **Cleanup**: Use `back` to deselect clients when done
5. **Documentation**: Use `options` to see available configuration options

## Troubleshooting

### Common Issues

**Client not found:**
```bash
icssploit > use client/unknown
[-] Unknown client type: unknown
[+] Available types: bacnet, modbus, modbus_tcp, s7, s7plus, opcua, cip, wdb2, zmq
```

**Connection failed:**
```bash
icssploit (ZMQClient:zmq_client) > run
[*] Running client...
[-] Failed to connect to zmq_client
```

**Method not found:**
```bash
icssploit (ZMQClient:zmq_client) > call unknown_method
[-] Method unknown_method not found on client ZMQClient
```

### Getting Help

- Use `show clients` to see all available client types
- Use `options` to see available configuration options for the current client
- Use `help` to see available commands in the current context 