# config-runner
Script used to push out commands (single or a batch) across network devices, capture received output, and save output to individual log files.

# Use Case
Run commands (single or a batch) out to specified network devices.

# Requirements
* Python 3
* netmiko, ping3, validators (see requirements.txt)
* Root or administrator privileges required for ICMP reachability checks (ping3)

# Device List Format
Each line in the device list file defines one host using semicolon-delimited `attribute:value` pairs.

| Attribute     | Mandatory | Description                                              |
|---------------|-----------|----------------------------------------------------------|
| `hostname`    | Yes       | DNS name or IPv4 address of the target host              |
| `device_type` | Yes       | Netmiko device type (default: `cisco_ios`)               |
| `commands`    | Yes       | Path to the command file to run on this host             |
| `username`    | No        | Login username (prompted at runtime if omitted)          |
| `password`    | No        | Login password (prompted at runtime if omitted)          |
| `secret`      | No        | Enable/Priv15 passphrase                                 |

Example device list entry:
```
hostname:192.168.1.1;device_type:cisco_ios;username:admin;password:;secret:;commands:commands.log
```

Lines beginning with `#` are treated as comments. See `devices-sample.log` for a full example.

> **Note:** Storing passwords in cleartext device files is not recommended. Leave `password` and `secret` blank and use `--login` to prompt for credentials at runtime instead.

# Command File Format
Commands must be wrapped in block markers that indicate whether they run in read (exec) or write (config) mode. This is required by how Netmiko handles each mode.

#### Read block — exec mode (show commands)
```
!read_block
show inventory
show version
!read_block
```

#### Write block — config mode (configuration changes)
```
!write_block
interface loopback100
 description test config
!write_block
```

#### Save configuration
```
!save
```

See `commands-sample.log` for a full example combining all block types.

# Setup
```
python3 -m pip install -r requirements.txt
```

# Usage
```
config_runner.py [-h] [--list_device LIST_DEVICE] [--list_command LIST_COMMAND] [--device DEVICE] [--command COMMAND] [--output OUTPUT] [--threads THREADS] [--verbose] [--login] [--save]
```
- Accepts device and command input via files or directly through CLI arguments
- Run with `--help` for full argument details
- See attached sample files for input format reference

# Flags

| Flag              | Description                                                                                     |
|-------------------|-------------------------------------------------------------------------------------------------|
| `--list_device`   | Device list file. Each line defines a host and its associated command file.                    |
| `--device`        | Single host (DNS name or IP) to target.                                                        |
| `--list_command`  | Command file to run across all devices.                                                        |
| `--command`       | Single read-only command to run across all devices.                                            |
| `--output`        | Output directory for log files. Defaults to `./config-runner-logs`.                           |
| `--threads`       | Number of concurrent threads (default: 10, max: 100).                                         |
| `--login`         | Prompt for a single set of credentials to use across all devices, overriding the device file. |
| `--save`          | Issue a configuration save (`write mem`) across targeted devices. Overrides all other commands when passed via CLI. To combine a save with other commands, include `!save` in your command file instead. |
| `--verbose`       | Enable verbose console output.                                                                 |

# Examples

```
# Run a device file — credentials included in the device file
python3 config_runner.py --list_device devices.log

# Run a device file with dynamic credentials (prompted at runtime)
python3 config_runner.py --list_device devices.log --login

# Run a single command across all devices in a device file
python3 config_runner.py --list_device devices.log --command "show run"
python3 config_runner.py --list_device devices.log --command "show version"
python3 config_runner.py --list_device devices.log --command "show inventory"

# Run a command file against a single device
python3 config_runner.py --device 172.16.224.2 --list_command show_commands.log

# Run a single command against a single device
python3 config_runner.py --device 172.16.224.2 --command "show run"

# Enable verbose output
python3 config_runner.py --device 172.16.224.2 --command "show run" --verbose

# Specify an output directory
python3 config_runner.py --device 172.16.224.2 --list_command show_version.log --output "test-output"
python3 config_runner.py --device 172.16.224.2 --list_command show_version.log --output "../test-output"

# Set thread count
python3 config_runner.py --list_device devices.log --threads 100

# Save configuration on a single device or across a device list
python3 config_runner.py --device 1.1.1.1 --save
python3 config_runner.py --list_device devices.log --save
```
