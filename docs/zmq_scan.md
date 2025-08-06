# 0MQ Scanner Module

The 0MQ scanner module allows you to discover and enumerate 0MQ (ZeroMQ) devices on the network.

## Features

- **Device Discovery**: Scan for 0MQ devices using different socket types
- **Device Enumeration**: Enumerate device capabilities and properties
- **Permission Checking**: Check send/receive permissions for different operations
- **Port Scanning**: Use TCP port scanning to find 0MQ devices
- **Export Results**: Export scan results to CSV format
- **Multiple Transport Support**: Support for TCP, IPC, and INPROC transports
- **Socket Type Testing**: Test different 0MQ socket types (REQ, SUB, PUB, etc.)

## Usage

### Basic Scan

```bash
use scanners/zmq_scan
set target 192.168.1.0/24
run
```

### Advanced Scan with Enumeration

```bash
use scanners/zmq_scan
set target 192.168.1.0/24
set enumerate true
set check_permissions true
set socket_types REQ,SUB,PUB
set start_port 5555
set end_port 5565
run
```

### Export Results

```bash
use scanners/zmq_scan
set target 192.168.1.0/24
run
export zmq_devices.csv
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target network range (CIDR notation) | Required |
| `port` | 0MQ port to scan | 5555 |
| `start_port` | Start port for device discovery | 5555 |
| `end_port` | End port for device discovery | 5565 |
| `socket_types` | Comma-separated list of socket types to test | REQ,SUB |
| `transport` | Transport protocol: TCP, IPC, INPROC | TCP |
| `enumerate` | Enumerate device capabilities and properties | false |
| `check_permissions` | Check send/receive permissions | false |

## Output

The scanner provides the following information for each discovered device:

- **Socket Type**: 0MQ socket type (REQ, SUB, PUB, etc.)
- **Transport**: Transport protocol (TCP, IPC, INPROC)
- **Status**: Device status (online/offline)
- **Accessible**: Whether device is accessible
- **Address**: Device IP address
- **Port**: Device port

## Example Output

```
[+] Found 3 0MQ devices
+------------+----------+--------+----------+-------------+------+
| Socket Type| Transport| Status | Accessible| Address     | Port |
+------------+----------+--------+----------+-------------+------+
| REQ        | TCP      | online | True      | 192.168.1.10| 5555 |
| SUB        | TCP      | online | True      | 192.168.1.11| 5556 |
| PUB        | TCP      | online | True      | 192.168.1.12| 5557 |
+------------+----------+--------+----------+-------------+------+
```

## 0MQ Device Control

The 0MQ device control module allows you to interact with individual 0MQ devices.

### Usage

```bash
use exploits/plcs/zmq/zmq_device_control
set target 192.168.1.10
set operation send
set message "Hello World"
run
```

### Operations

1. **Send**: Send messages to 0MQ devices
2. **Receive**: Receive messages from 0MQ devices
3. **Request-Reply**: Send requests and receive replies
4. **Subscribe**: Subscribe to topics and receive messages
5. **Enumerate**: Enumerate device capabilities
6. **Permissions**: Check send/receive permissions

### Socket Types

- `REQ`: Request socket (synchronous request-reply)
- `REP`: Reply socket (synchronous request-reply)
- `PUB`: Publish socket (asynchronous publish-subscribe)
- `SUB`: Subscribe socket (asynchronous publish-subscribe)
- `PUSH`: Push socket (asynchronous pipeline)
- `PULL`: Pull socket (asynchronous pipeline)
- `PAIR`: Pair socket (exclusive pair)
- `DEALER`: Dealer socket (asynchronous client-server)
- `ROUTER`: Router socket (asynchronous client-server)

### Transport Protocols

- `TCP`: TCP transport (default)
- `IPC`: Inter-process communication
- `INPROC`: In-process communication

### Examples

#### Send Message
```bash
use exploits/plcs/zmq/zmq_device_control
set target 192.168.1.10
set operation send
set message "Hello World"
set socket_type REQ
run
```

#### Receive Messages
```bash
use exploits/plcs/zmq/zmq_device_control
set target 192.168.1.10
set operation receive
set socket_type SUB
set count 5
set timeout 10
run
```

#### Request-Reply
```bash
use exploits/plcs/zmq/zmq_device_control
set target 192.168.1.10
set operation request_reply
set message "PING"
set socket_type REQ
run
```

#### Subscribe to Topic
```bash
use exploits/plcs/zmq/zmq_device_control
set target 192.168.1.10
set operation subscribe
set topic "status"
set socket_type SUB
set count 3
run
```

#### Publish Message
```bash
use exploits/plcs/zmq/zmq_device_control
set target 192.168.1.10
set operation send
set message "System Status: OK"
set topic "status"
set socket_type PUB
run
```

#### Enumerate Device
```bash
use exploits/plcs/zmq/zmq_device_control
set target 192.168.1.10
set operation enumerate
run
```

#### Check Permissions
```bash
use exploits/plcs/zmq/zmq_device_control
set target 192.168.1.10
set operation permissions
run
```

## 0MQ Communication Patterns

### Request-Reply Pattern
- **REQ Socket**: Sends requests and receives replies
- **REP Socket**: Receives requests and sends replies
- **Use Case**: Synchronous client-server communication

### Publish-Subscribe Pattern
- **PUB Socket**: Publishes messages to topics
- **SUB Socket**: Subscribes to topics and receives messages
- **Use Case**: Asynchronous messaging, broadcasting

### Pipeline Pattern
- **PUSH Socket**: Sends messages to downstream
- **PULL Socket**: Receives messages from upstream
- **Use Case**: Load balancing, parallel processing

### Exclusive Pair Pattern
- **PAIR Socket**: Bidirectional communication between two peers
- **Use Case**: Direct peer-to-peer communication

### Asynchronous Client-Server Pattern
- **DEALER Socket**: Asynchronous client
- **ROUTER Socket**: Asynchronous server
- **Use Case**: Multi-threaded client-server applications

## Common 0MQ Ports

### Default Ports
- 5555: Default 0MQ port
- 5556: Alternative 0MQ port
- 5557: Additional 0MQ port
- 5558-5565: Extended 0MQ port range

### Common Topics
- `status`: System status messages
- `data`: Data messages
- `control`: Control messages
- `info`: Information messages
- `alarm`: Alarm messages
- `config`: Configuration messages

## Security Considerations

⚠️ **Warning**: 0MQ devices may control critical industrial systems. Always:

1. **Test in a safe environment** before running against production systems
2. **Verify permissions** before sending messages
3. **Use appropriate socket types** for your use case
4. **Implement proper authentication** in production environments
5. **Monitor message traffic** for suspicious activity
6. **Use secure transports** (WSS, TLS) when available

## 0MQ Best Practices

### Message Format
- Use consistent message formats
- Include message headers when needed
- Implement message validation
- Use appropriate encoding (JSON, Protocol Buffers, etc.)

### Error Handling
- Implement timeout handling
- Handle connection failures gracefully
- Log errors appropriately
- Implement retry mechanisms

### Performance
- Use appropriate socket types for your use case
- Implement message batching when possible
- Monitor message queue sizes
- Use high-water marks to prevent memory issues

### Security
- Implement authentication and authorization
- Use encrypted transports when possible
- Validate all incoming messages
- Implement rate limiting
- Monitor for unusual message patterns 