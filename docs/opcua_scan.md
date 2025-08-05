# OPC UA Scanner Module

The OPC UA scanner module allows you to discover and enumerate OPC UA servers on the network.

## Features

- **Server Discovery**: Scan for OPC UA servers using port scanning and server discovery
- **Server Enumeration**: Enumerate server nodes and properties
- **Permission Checking**: Check read/write permissions for different node types
- **Endpoint Discovery**: Get server endpoints and security policies
- **Export Results**: Export scan results to CSV format
- **Security Support**: Support for various security policies and modes
- **Authentication**: Support for username/password authentication
- **Brute Force**: Credential brute force capabilities

## Usage

### Basic Scan

```bash
use scanners/opcua_scan
set target 192.168.1.0/24
run
```

### Advanced Scan with Enumeration

```bash
use scanners/opcua_scan
set target 192.168.1.0/24
set enumerate true
set check_permissions true
set get_endpoints true
set security_policy None
set security_mode None
run
```

### Scan with Authentication

```bash
use scanners/opcua_scan
set target 192.168.1.0/24
set username admin
set password password123
set security_policy Basic128Rsa15
set security_mode Sign
run
```

### Export Results

```bash
use scanners/opcua_scan
set target 192.168.1.0/24
run
export opcua_servers.csv
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target network range (CIDR notation) | Required |
| `port` | OPC UA port to scan | 4840 |
| `security_policy` | Security policy | None |
| `security_mode` | Security mode | None |
| `username` | Username for authentication | (empty) |
| `password` | Password for authentication | (empty) |
| `enumerate` | Enumerate server nodes and properties | false |
| `check_permissions` | Check read/write permissions | false |
| `get_endpoints` | Get server endpoints | false |

## Output

The scanner provides the following information for each discovered server:

- **Server Name**: Name of the OPC UA server
- **Server URI**: Server URI identifier
- **Application URI**: Application URI
- **Product URI**: Product URI
- **Software Version**: Software version
- **Build Number**: Build number

## Example Output

```
[+] Found 2 OPC UA server(s)
+-------------+-------------+------------------+-------------+------------------+-------------+
| Server Name | Server URI  | Application URI  | Product URI | Software Version | Build Number|
+-------------+-------------+------------------+-------------+------------------+-------------+
| TestServer  | urn:test    | urn:test:app     | urn:test:prod| 1.0.0           | 1234        |
| DemoServer  | urn:demo    | urn:demo:app     | urn:demo:prod| 2.1.0           | 5678        |
+-------------+-------------+------------------+-------------+------------------+-------------+
```

## OPC UA Device Control

The OPC UA device control module allows you to interact with individual OPC UA servers.

### Usage

```bash
use exploits/plcs/opcua/opcua_device_control
set target 192.168.1.10
set operation read
set node_id i=84
run
```

### Operations

1. **Read**: Read node values from OPC UA servers
2. **Write**: Write values to OPC UA nodes
3. **Browse**: Browse server nodes starting from a specific node
4. **Call Method**: Call methods on OPC UA objects
5. **Enumerate**: Enumerate all nodes and properties on a server
6. **Permissions**: Check read/write permissions for different node types
7. **Brute Force**: Brute force server credentials

### Examples

#### Read Node
```bash
use exploits/plcs/opcua/opcua_device_control
set target 192.168.1.10
set operation read
set node_id i=84
run
```

#### Write to Node
```bash
use exploits/plcs/opcua/opcua_device_control
set target 192.168.1.10
set operation write
set node_id i=84
set value "test_value"
run
```

#### Browse Nodes
```bash
use exploits/plcs/opcua/opcua_device_control
set target 192.168.1.10
set operation browse
set browse_path i=85
set max_results 20
run
```

#### Call Method
```bash
use exploits/plcs/opcua/opcua_device_control
set target 192.168.1.10
set operation call_method
set object_node_id i=85
set method_node_id i=1234
set arguments "arg1,arg2,arg3"
run
```

#### Enumerate Device
```bash
use exploits/plcs/opcua/opcua_device_control
set target 192.168.1.10
set operation enumerate
run
```

#### Brute Force Credentials
```bash
use exploits/plcs/opcua/opcua_device_control
set target 192.168.1.10
set operation brute_force
set password_wordlist passwords.txt
set username_wordlist usernames.txt
set brute_force_delay 1.0
run
```

## OPC UA Node Types

### Common Node IDs

| Node ID | Description |
|---------|-------------|
| `i=84` | Root |
| `i=85` | Objects |
| `i=86` | Types |
| `i=87` | Views |
| `i=88` | Methods |
| `i=2253` | Server |

### Node Classes

- **Object**: Objects that can contain other nodes
- **Variable**: Variables that hold values
- **Method**: Methods that can be called
- **ObjectType**: Object type definitions
- **VariableType**: Variable type definitions
- **ReferenceType**: Reference type definitions
- **DataType**: Data type definitions
- **View**: Views that provide filtered access to nodes

## OPC UA Security

### Security Policies

- **None**: No security
- **Basic128Rsa15**: Basic 128-bit RSA security
- **Basic256**: Basic 256-bit security
- **Basic256Sha256**: Basic 256-bit SHA256 security

### Security Modes

- **None**: No security
- **Sign**: Message signing
- **SignAndEncrypt**: Message signing and encryption

## Common OPC UA Browse Paths

### Root Level (i=84)
- Server information
- Configuration data
- System status

### Objects (i=85)
- Application objects
- Device objects
- Process objects
- Control objects

### Types (i=86)
- Object types
- Variable types
- Data types
- Reference types

### Views (i=87)
- Custom views
- Filtered node sets
- Application-specific views

### Methods (i=88)
- Server methods
- Application methods
- Control methods

## Security Considerations

⚠️ **Warning**: OPC UA servers may control critical industrial systems. Always:

1. **Test in a safe environment** before running against production systems
2. **Verify permissions** before writing to nodes
3. **Use appropriate security settings** for your environment
4. **Monitor system responses** to ensure safe operation
5. **Follow local security policies** and regulations
6. **Be aware of node access levels** to avoid critical system areas
7. **Use secure authentication** when available
8. **Respect rate limits** to avoid overwhelming servers

## Troubleshooting

### No Servers Found
- Check network connectivity
- Verify OPC UA port (4840) is not blocked
- Check if servers support OPC UA TCP
- Verify security settings match server configuration
- Try different security policies/modes

### Connection Errors
- Verify target IP address and port
- Check firewall settings
- Ensure OPC UA service is running on target server
- Verify security settings
- Check authentication credentials

### Permission Errors
- Some nodes may be read-only
- Check server security settings
- Verify user permissions on target server
- Some nodes may be protected by access control
- Check node access levels

### Security Policy Issues
- Verify server supports the specified security policy
- Check certificate configuration
- Ensure security mode matches server requirements
- Try different security combinations

### Authentication Issues
- Verify username/password are correct
- Check if server requires authentication
- Ensure authentication method is supported
- Try anonymous access if available

## Dependencies

The OPC UA module requires the `opcua` library:

```bash
pip install opcua
```

This provides support for OPC UA client functionality including:
- Server discovery
- Node browsing and reading
- Security policies and modes
- Authentication
- Method calls 