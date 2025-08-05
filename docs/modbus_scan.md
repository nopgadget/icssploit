# Modbus Scanner Module

The Modbus scanner module allows you to discover and enumerate Modbus devices on the network.

## Features

- **Device Discovery**: Scan for Modbus devices using unit ID scanning
- **Device Enumeration**: Enumerate device registers and properties
- **Permission Checking**: Check read/write permissions for different register types
- **Port Scanning**: Use TCP port scanning to find Modbus devices
- **Export Results**: Export scan results to CSV format
- **TCP/RTU Support**: Support for both Modbus TCP and RTU protocols

## Usage

### Basic Scan

```bash
use scanners/modbus_scan
set target 192.168.1.0/24
run
```

### Advanced Scan with Enumeration

```bash
use scanners/modbus_scan
set target 192.168.1.0/24
set enumerate true
set check_permissions true
set start_unit_id 1
set end_unit_id 20
run
```

### Export Results

```bash
use scanners/modbus_scan
set target 192.168.1.0/24
run
export modbus_devices.csv
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target network range (CIDR notation) | Required |
| `port` | Modbus port to scan | 502 |
| `device_type` | Device type: TCP or RTU | TCP |
| `start_unit_id` | Start unit ID for device discovery | 1 |
| `end_unit_id` | End unit ID for device discovery | 10 |
| `enumerate` | Enumerate device registers and properties | false |
| `check_permissions` | Check read/write permissions | false |

## Output

The scanner provides the following information for each discovered device:

- **Device Type**: TCP or RTU
- **Unit ID**: Modbus unit ID
- **Status**: Device status (online/offline)
- **Registers Accessible**: Whether registers are accessible
- **Address**: Device IP address
- **Port**: Device port

## Example Output

```
[+] Found 2 Modbus devices
+-------------+---------+--------+----------------------+-------------+------+
| Device Type | Unit ID | Status | Registers Accessible | Address     | Port |
+-------------+---------+--------+----------------------+-------------+------+
| TCP         | 1       | online | True                 | 192.168.1.10| 502  |
| TCP         | 2       | online | True                 | 192.168.1.11| 502  |
+-------------+---------+--------+----------------------+-------------+------+
```

## Modbus Device Control

The Modbus device control module allows you to interact with individual Modbus devices.

### Usage

```bash
use exploits/plcs/modbus/modbus_device_control
set target 192.168.1.10
set operation read
set register_type holding_registers
set address 0
set count 10
run
```

### Operations

1. **Read**: Read register values from Modbus devices
2. **Write**: Write values to Modbus registers
3. **Command**: Execute commands on Modbus devices
4. **Enumerate**: Enumerate all registers and properties on a device
5. **Permissions**: Check read/write permissions for different register types

### Register Types

- `coils`: Read/Write coils (boolean values)
- `discrete_inputs`: Read-only discrete inputs (boolean values)
- `holding_registers`: Read/Write holding registers (16-bit values)
- `input_registers`: Read-only input registers (16-bit values)

### Examples

#### Read Holding Registers
```bash
use exploits/plcs/modbus/modbus_device_control
set target 192.168.1.10
set operation read
set register_type holding_registers
set address 0
set count 10
run
```

#### Write to Holding Register
```bash
use exploits/plcs/modbus/modbus_device_control
set target 192.168.1.10
set operation write
set register_type holding_registers
set address 0
set value 123
run
```

#### Write Multiple Coils
```bash
use exploits/plcs/modbus/modbus_device_control
set target 192.168.1.10
set operation write
set register_type coils
set address 0
set values true,false,true,false
run
```

#### Execute Command
```bash
use exploits/plcs/modbus/modbus_device_control
set target 192.168.1.10
set operation command
set register_type coils
set address 0
set value true
run
```

#### Enumerate Device
```bash
use exploits/plcs/modbus/modbus_device_control
set target 192.168.1.10
set operation enumerate
run
```

## Modbus Function Codes

| Function Code | Name | Description |
|---------------|------|-------------|
| 0x01 | Read Coils | Read multiple coils |
| 0x02 | Read Discrete Inputs | Read multiple discrete inputs |
| 0x03 | Read Holding Registers | Read multiple holding registers |
| 0x04 | Read Input Registers | Read multiple input registers |
| 0x05 | Write Single Coil | Write single coil |
| 0x06 | Write Single Register | Write single register |
| 0x0F | Write Multiple Coils | Write multiple coils |
| 0x10 | Write Multiple Registers | Write multiple registers |

## Common Modbus Register Addresses

### Holding Registers (40001-49999)
- 40001-40099: System configuration
- 40100-40199: Device parameters
- 40200-40299: Process variables
- 40300-40399: Alarm settings
- 40400-40499: Communication settings

### Input Registers (30001-39999)
- 30001-30099: System status
- 30100-30199: Device status
- 30200-30299: Process values
- 30300-30399: Alarm status
- 30400-30499: Communication status

### Coils (00001-09999)
- 00001-00099: System control
- 00100-00199: Device control
- 00200-00299: Process control
- 00300-00399: Alarm control
- 00400-00499: Communication control

### Discrete Inputs (10001-19999)
- 10001-10099: System status
- 10100-10199: Device status
- 10200-10299: Process status
- 10300-10399: Alarm status
- 10400-10499: Communication status

## Security Considerations

⚠️ **Warning**: Modbus devices may control critical industrial systems. Always:

1. **Test in a safe environment** before running against production systems
2. **Verify permissions** before writing to registers
3. **Use appropriate unit IDs** for device communication
4. **Monitor system responses** to ensure safe operation
5. **Follow local security policies** and regulations
6. **Be aware of register address ranges** to avoid critical system areas

## Troubleshooting

### No Devices Found
- Check network connectivity
- Verify Modbus port (502) is not blocked
- Try increasing unit ID range
- Check if devices support Modbus TCP
- For RTU devices, verify serial port settings

### Connection Errors
- Verify target IP address
- Check firewall settings
- Ensure Modbus service is running on target device
- Verify unit ID is correct

### Permission Errors
- Some registers may be read-only
- Check device security settings
- Verify user permissions on target device
- Some registers may be protected by access control

### RTU Mode Issues
- Verify serial port is available
- Check baud rate, data bits, stop bits, and parity settings
- Ensure proper serial cable connection
- Verify device supports Modbus RTU protocol

## Dependencies

The Modbus module requires the `pymodbus` library:

```bash
pip install pymodbus[serial]
```

This provides support for both Modbus TCP and RTU protocols. 