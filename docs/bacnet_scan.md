# BACnet Scanner Module

The BACnet scanner module allows you to discover and enumerate BACnet devices on the network.

## Features

- **Device Discovery**: Scan for BACnet devices using Who-Is requests
- **Device Enumeration**: Enumerate device objects and properties
- **Permission Checking**: Check read/write permissions for device properties
- **Port Scanning**: Use UDP port scanning to find BACnet devices
- **Export Results**: Export scan results to CSV format

## Usage

### Basic Scan

```bash
use scanners/bacnet_scan
set target 192.168.1.0/24
run
```

### Advanced Scan with Enumeration

```bash
use scanners/bacnet_scan
set target 192.168.1.0/24
set enumerate true
set check_permissions true
set timeout 15
run
```

### Export Results

```bash
use scanners/bacnet_scan
set target 192.168.1.0/24
run
export bacnet_devices.csv
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target network range (CIDR notation) | Required |
| `port` | BACnet port to scan | 47808 |
| `timeout` | Discovery timeout in seconds | 10 |
| `enumerate` | Enumerate device objects and properties | false |
| `check_permissions` | Check read/write permissions | false |

## Output

The scanner provides the following information for each discovered device:

- **Device Name**: Object name of the device
- **Vendor Name**: Manufacturer name
- **Model Name**: Device model
- **Firmware Version**: Firmware version
- **System Status**: Current system status
- **Max APDU Length**: Maximum APDU length accepted
- **IP Address**: Device IP address

## Example Output

```
[+] Found 3 BACnet devices
+-------------+-------------+-------------+------------------+---------------+------------------+-------------+
| Device Name | Vendor Name | Model Name  | Firmware Version | System Status | Max APDU Length  | IP Address  |
+-------------+-------------+-------------+------------------+---------------+------------------+-------------+
| HVAC-01     | Johnson     | FX-80       | V3.2.1          | operational   | 1476             | 192.168.1.10|
| VAV-02      | Honeywell   | T7350       | V2.1.0          | operational   | 1476             | 192.168.1.11|
| RTU-03      | Carrier     | 50TC        | V4.0.2          | operational   | 1476             | 192.168.1.12|
+-------------+-------------+-------------+------------------+---------------+------------------+-------------+
```

## BACnet Device Control

The BACnet device control module allows you to interact with individual BACnet devices.

### Usage

```bash
use exploits/plcs/bacnet/bacnet_device_control
set target 192.168.1.10
set operation read
set object_id device,1
set property_id objectName
run
```

### Operations

1. **Read**: Read property values from BACnet objects
2. **Write**: Write values to BACnet object properties
3. **Command**: Execute commands on BACnet objects
4. **Enumerate**: Enumerate all objects and properties on a device
5. **Permissions**: Check read/write permissions for properties

### Commands

- `set_value`: Set the present value of an object
- `enable`: Enable an object (set outOfService to false)
- `disable`: Disable an object (set outOfService to true)

### Examples

#### Read Device Name
```bash
use exploits/plcs/bacnet/bacnet_device_control
set target 192.168.1.10
set operation read
set object_id device,1
set property_id objectName
run
```

#### Write to Analog Output
```bash
use exploits/plcs/bacnet/bacnet_device_control
set target 192.168.1.10
set operation write
set object_id analogOutput,1
set property_id presentValue
set value 75.5
run
```

#### Execute Command
```bash
use exploits/plcs/bacnet/bacnet_device_control
set target 192.168.1.10
set operation command
set object_id analogOutput,1
set command set_value
set value 50.0
set priority 16
run
```

#### Enumerate Device
```bash
use exploits/plcs/bacnet/bacnet_device_control
set target 192.168.1.10
set operation enumerate
run
```

## Common BACnet Object Types

- `device`: Device object
- `analogInput`: Analog input point
- `analogOutput`: Analog output point
- `analogValue`: Analog value point
- `binaryInput`: Binary input point
- `binaryOutput`: Binary output point
- `binaryValue`: Binary value point
- `multiStateInput`: Multi-state input point
- `multiStateOutput`: Multi-state output point
- `multiStateValue`: Multi-state value point

## Common BACnet Properties

- `objectName`: Object name
- `presentValue`: Current value
- `description`: Object description
- `units`: Units of measurement
- `statusFlags`: Status flags
- `reliability`: Reliability status
- `outOfService`: Out of service flag
- `vendorName`: Vendor name
- `modelName`: Model name
- `firmwareRevision`: Firmware version

## Security Considerations

⚠️ **Warning**: BACnet devices may control critical building systems. Always:

1. **Test in a safe environment** before running against production systems
2. **Verify permissions** before writing to devices
3. **Use appropriate priority levels** for commands
4. **Monitor system responses** to ensure safe operation
5. **Follow local security policies** and regulations

## Troubleshooting

### No Devices Found
- Check network connectivity
- Verify BACnet port (47808) is not blocked
- Try increasing timeout value
- Check if devices support BACnet/IP

### Connection Errors
- Verify target IP address
- Check firewall settings
- Ensure BACnet service is running on target device

### Permission Errors
- Some properties may be read-only
- Check device security settings
- Verify user permissions on target device 