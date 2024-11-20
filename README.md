# config-runner
Script used to push out commands (single or a batch) to defined network device/s, capture all the received output and save the output to individual log files.

# Use Case
Run commands (single or a batch) out to specified network devices.

# Requirements
* Python3
* Select Python libraries (netmiko, ping3, validators)

#Device List Format
Commands which to be issued on devices must be placed within a 'block'. These blocks denote whether commands are run in configuration mode (i.e. configuration changes) or base privilege mode (show commands). This is required due to the way Netmiko issues commands to each device.

See below for sample configuration file blocks:

#### Read_block Example ####
!read_block
show inventory
show version
!read_block

#### Write_block Example ####
!write_block 
interface loopback100
 desc this is some test config 
!write_block

#### Save Example ####
!save

# Setup
`py -3 -m pip install netmiko ping3 validators`

# Usage
`config_runnner.py [-h] [--list_device LIST_DEVICE] [--list_command LIST_COMMAND] [--device DEVICE] [--command COMMAND] [--output OUTPUT] [--threads THREADS] [--verbose] [--login]`
-	The script is capable of taking input files, regarding device/command information, or providing directly via command line args.
-	I have attached samples of both device and command inputs for reference.
-	Issue --help flag to script for additional input details

# Examples
#### Run device file containing all details (username/password/secret included in device file) ####

`py -3 config_runnner.py --list_device devices.log`

**Note:** Expects password in device file. Where security is a concern leave the login details out and the script will dynamically prompt for this information.

#### Run device file and a dynamic set of credentials (username/password/secret excluded from provided file) ####

`py -3 config_runnner.py --list_device devices.log --login`

**Note:** You will be prompted for a single account prior to threads initiating


#### Run a device file with command directly in the cli (only single command supported) ####
`py -3 config_runnner.py --list_device devices.log --command "show run"`

`py -3 config_runnner.py --list_device devices.log --command "show version"`

`py -3 config_runnner.py --list_device devices.log --command "show inventory"`

**Note:** Useful for a quick ‘show run’ or ‘show inv’ across several devices

#### Run a command file across a single device ####
`py -3 config_runnner.py --device 172.16.224.2 --list_command show_commands.log`

#### Run a single command to a single device (all on CLI) ####
`py -3 config --device 172.16.224.2 --command “show run”`

#### Enable verbose logging ####
`py -3 config --device 172.16.224.2 --command “show run” --verbose`

#### Define the output location ####
`py -3 config_runnner.py --device 172.16.224.2 --list_command show_version.log --output “test-output”`

`py -3 config_runnner.py --device 172.16.224.2 --list_command show_version.log --output “C:\Users\username\source\repos\config-runnner\config-runnner\test-output\”`

`py -3 config_runnner.py --device 172.16.224.2 --list_command show_version.log --output “../test-output”`

**Note:** The default output directory is same directory as script
&nbsp;&nbsp;
#### Change number of threads (scales to x100) ####
`py -3 config_runnner.py --list_device devices.log --thread 100`

**Note:** Default threads = x10

#### Save configuration across a device or group of devices ####
`py -3 config_runnner.py --device 1.1.1.1 --save`

`py -3 config_runnner.py --list_device --save`

**Note:** Useful to save configuration across one or several endpoints