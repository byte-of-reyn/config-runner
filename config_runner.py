#!/usr/bin/python3
#config_runner.py : CLI tool used to push out configuration/commands to network devices

__author__ = 'allen.reyn'
__version__ = '0.40'

from datetime import datetime
from getpass import getpass
from queue import Queue
from ping3 import ping, verbose_ping
from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException
from threading import Lock

import threading
import getpass
import argparse
import requests
import sys
import os.path
import signal
import os
import re
import time
import validators
import traceback

VERSION = '0.40'
RELEASE_DATE = '30 Sep 2023'
AUTHOR = 'areyn'

DEVICE_TYPE = 1
HOST = 0
USERNAME = 2
PASSWORD = 3
SECRET = 5
COMMANDS = 4

BLOCK_TYPE = 0
BLOCK_CLI = 1

THREAD_SUMMARY = 0
THREAD_ID = 1
THREAD_STATUS = 2

verbose = False
dynamic_account = False
num_threads = 10
max_threads = 100
thread_queue = Queue()
print_lock = threading.Lock()
success_count = 0
fail_count = 0

class Device():
    hostname = ''
    device_type = ''
    username = ''
    password = ''
    secret = ''
    commands = []
    
    def __init__(self, name, user, password, secret, device_type, commands):
        self.hostname = name
        self.username = user
        self.device_type = device_type
        self.password = password
        self.secret = secret
        self.commands = []

    def add_command(self, cmd):
        self.commands.append(cmd)

    def update_attribute(self, attr, value):
        result = False
        #print("Attr: {} - Value: {}".format(attr, value))
        if attr == 'hostname':
            self.hostname = value
            result = True
        if attr == 'device_type':
            self.device_type = value
            result = True
        if attr == 'username':
            self.username = value
            result = True
        if attr == 'password':
            self.password = value
            result = True
        if attr == 'secret':
            self.secret = value
            result = True
        if attr == 'commands':
            self.add_command(value)
            result = True
        return result

    #checks if device contains sufficient detail to pass onto Netmiko function
    def valid_check(self):
        contains_data = re.compile(r'^[\w\d\D]+$')
        min_config = 0
        required_items = 5
        if re.match(contains_data, self.hostname):
            min_config += 1
        if re.match(contains_data, str(self.commands[0])):
            min_config += 1
        if re.match(contains_data, self.username):
            min_config += 1
        if re.match(contains_data, self.password):
            min_config += 1
        if re.match(contains_data, self.device_type):
            min_config += 1
        if min_config >= required_items:
            return True
        else:
            return False

#removes whitespace and newlines surrounding string
def clean_input(string):
    tempString = string
    tempString = tempString.strip().replace('\n', '')
    return tempString

#appends datetime onto passed string
def append_datetime(string):
    temp_string = datetime.now()
    temp_string = temp_string.strftime('%y%m%d-%H%M%S')
    return string + '_' + temp_string

#reads in file contents and returns an array containing contents
def read_file(filename):
    tempArr = []
    try:
        file = open(filename, "r")
        for line in file:
            tempArr.append(clean_input(line))
        file.close()
    except Exception as err:
        print('Error reading input file {}.\n'.format(filename))
    return tempArr

#writes string to output file
def write_file(string, outputName):
    try:
        file = open(outputName, "w")
        file.write(string)
        file.close()
    except Exception as err:
        print('Error writing file.\n', err)

#writes array to output file
def write_file_array(array, outputName):
    try:
        file = open(outputName, "w")
        for entry in array:
            file.write(entry)
            file.write("\n")
        file.close()
    except Exception as err:
        print('Error writing file.\n', err)

#checks if file is valid
def is_valid_file(file):
    valid = None
    if os.path.isfile(file):
        valid = True
    return valid

#checks for a valid cisco command
def check_cisco_command(cmd):
    illegal_char = re.compile(r'([@#$%^&*()<>?\'"{[}\]|\\`~]+)')
    empty = r'^\s*$'
    is_empty = re.match(empty, cmd)
    is_illegal = re.match(illegal_char, cmd)
    if is_empty or is_illegal:
        return False
    else:
        return True

#dynamically obtains account details for devices
def get_account():
    empty = r'^\s*$'
    account =   {
                    'username': '',
                    'password': '',
                    'secret': '',
                }

    account['username'] = input('Username: ')
    while re.match(empty, account['username']) or account['username'] == '':
        account['username'] = input('Username: ')
    account['password'] = getpass.getpass(prompt='Password: ', stream=None)
    while re.match(empty, account['password']) or account['password'] == '':
        account['password'] = getpass.getpass(prompt='Password: ', stream=None)
    print('\nINFO: Leave secret blank to run commands in the default priviledge-level.')
    account['secret'] = getpass.getpass(prompt='Secret: ', stream=None)
    return account

#parses arguments provided by the user
def parse_args(log_file):
    valid_ipv4 = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    valid_thread_no = re.compile(r'^[0-9]+\s*$')
    cli_command = False
    
    #setup parser
    parser = argparse.ArgumentParser(description='Runs out defined commands to a listing of devices.')
    parser.add_argument('--list_device', required=False, help='File input containing a listing of devices which commands will be run on.')
    parser.add_argument('--list_command', required=False, help='File input for commands to be run across all devices')
    parser.add_argument('--device', required=False, help='Hostname or IP address of device commands will be run on.')
    parser.add_argument('--command', required=False, help='Commands which will be run across the device listing')
    parser.add_argument('--output', required=False, help='Directory for results output location. Default is the same directory as the script.')
    parser.add_argument('--threads', required=False, help='Number of threads to utilise as part of capture activities. The default is 10.')
    parser.add_argument('--verbose', required=False, action='store_true', help='Verbose logging output.')
    parser.add_argument('--save', required=False, action='store_true', help='Only performs a configuration save across devices. Use the save flag via "list_command" file if you want to execute additional commands.')
    parser.add_argument('--login', required=False, action='store_true', help='Asks for dynamic input of device login details. Overrides any accounts provided via device list file.')
    args = parser.parse_args()

    #check for output location existence
    print()
    curr_dir = str(os.getcwd())
    if args.output != None:
        win_dir = re.compile(r'[a-zA-Z]:\\((?:.*?\\)*).*')
        same_dir_folder = re.compile(r'^\.\.\\.*')
        same_dir_folder02 = re.compile(r'^\.\./.*')
        save_dir = ''
        if re.match(win_dir, args.output):
            save_dir = args.output
        else:
            #..\\ type input provided via args
            if re.match(same_dir_folder, args.output) or re.match(same_dir_folder02, args.output) :
                save_dir = args.output.replace('.', '')
                save_dir = save_dir.replace('/', '')
                save_dir = save_dir.replace('\\', '')
                save_dir = curr_dir + '\\' + save_dir
            #assume only folder name provided - create new folder in same dir as script
            else:
                save_dir = curr_dir + '\\' + args.output
    #no output directory provided
    else:
        save_dir = curr_dir + '\\' + 'config-runner-logs'

    #check if save directory exists - create if required
    if not os.path.exists(save_dir):
        msg = "Output directory [{}] does not exist. Creating directory.".format(save_dir)
        if args.verbose:
            print("INFO: {}".format(msg))
        log_file.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
        os.makedirs(save_dir)
        msg = "Directory [{}] created.".format(save_dir)
        if args.verbose:
            print("INFO: {}".format(msg))
        log_file.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
    args.output = save_dir

    #check device list file validity
    if args.list_device:
        list_file = str(args.list_device)
        valid = is_valid_file(list_file)
        if not valid:
            print('ERROR: Unable to find device list file:', list_file)
            print("\nBREAK: Exiting program.")
            sys.exit(1)
        else:
            print('Device list: {}'.format(list_file))

    #check validity of provided host via args
    else:
        if args.device:
            valid_dn = str(validators.domain(args.device))
            if valid_dn:   
                print('Host: {}'.format(args.device))
            else:
                print('Not a valid host.')
                print("\nBREAK: Exiting program.")
                sys.exit(1)
        else:
            print('ERROR: No hosts provided to config-runner. Please provide via args or "list_device" input.')
            sys.exit(1) 

    #check provided thread count is valid
    if args.threads:
        threads = re.match(valid_thread_no, args.threads)
        if threads:
            if int(args.threads) <= max_threads:
                msg = 'Execution threads: x{}'.format(str(args.threads))
                print(msg)
                log_file.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
            else:
                print('Thread count x{} exceeds maximum of x100.'.format(args.threads))
                print('Exiting program.')
                sys.exit(1)
        else:
            print('Thread count is not a valid integer.')
            print('Exiting program.')
            sys.exit(1)
    else:
        args.threads = 10
        msg = 'Execution threads: x{}'.format(str(args.threads))
        print(msg)
        log_file.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))

    #check if user providing command to be run via CLI
    if args.command:
        print('Running command/s: {}'.format(args.command))
        print('\nWARNING: Commands provided via CLI args must be read-only!')
        cli_command = True
    elif args.list_command:
        print('Input command file: {}'.format(args.list_command))
        valid = is_valid_file(args.list_command)
        if not valid:
            print('Unable to find specified command file:', args.list_command)
            print('Exiting program.')
            sys.exit(1)
    else:
        if not args.list_device:
            print('\nERROR: No input commands provided. Please provide via --input_cmd or --command flags.')
            sys.exit(1)

    return args

#parse device commands
def parse_commands(cmd_list):
    cmd_blocks = []
    read_block = re.compile(r'^!read_block[/s]*.*')
    write_block = re.compile(r'^!write_block[/s]*.*')
    save_flag = re.compile(r'^!save[/s]*.*')
    
    #search for block start
    temp_cmds = []
    in_block = False

    #iterate through cmds and determine flag location
    for cmd in cmd_list:
        read_block_match = re.match(read_block, cmd)
        write_block_match = re.match(write_block, cmd)
        save_flag_match = re.match(save_flag, cmd)

        #currently inside of a command block
        if in_block:
            #found end of read block
            if read_block_match:
                in_block = False
                if len(temp_cmds) > 0:
                    temp_block = ("read_block", temp_cmds)
                    cmd_blocks.append(temp_block)
                temp_cmds = []    
            #found end of write block
            elif write_block_match:
                in_block = False
                if len(temp_cmds) > 0:
                    temp_block = ("write_block", temp_cmds)
                    cmd_blocks.append(temp_block)
                temp_cmds = []     
            else:
                temp_cmds.append(cmd)

        #currently outside of a command block
        else:            
            #found start of read block
            if read_block_match:
                in_block = True
            #found start of write block
            elif write_block_match:
                in_block = True
            #found save configuration flag
            elif save_flag_match: 
                temp_block = ("save_flag", "")
                cmd_blocks.append(temp_block)

    return cmd_blocks

#print header to console
def print_header():
    print("\n")
    print("*"*80)
    print("config_runner.py")
    print("*"*80)
    print("Version: {}".format(VERSION))
    print("Release Date: {}".format(RELEASE_DATE))
    print("Author: {}".format(AUTHOR))
    print("*"*80)

#print status to command line
def get_execute_summary(status):
    start_time = status['start_time']
    total_thread = status['total_thread']
    success_thread = status['success_thread']
    fail_thread = status['fail_thread']
    log_location = status['log_location']
    output_location = status['output_location']

    output = "\n"
    output += "*"*80
    output += "\nSCRIPT EXECUTION SUMMARY\n"
    output += "*"*80  
    output += "\nTotal Thread Count:\t{}".format(total_thread)
    output += "\nCompleted Thread Count:\t{}".format(success_thread)
    output += "\nFailed Thread Count:\t{}".format(fail_thread)
    output += "\nOutput File Location:\t{}".format(output_location)
    output += "\nEstimated runtime:\t{}\n".format(datetime.now()-start_time)
    output += "*"*80 

    return output

#compiles results of all executed threads
def get_thread_results(thread_results):
    output = "*"*80
    output += "\nTHREAD RESULTS OUTPUT\n"
    output += "*"*80 
    output += "\nHost ID\t\tThread ID\tExecution Status\n"
    output += "*"*80 
    output += "\n"
    for id, thread in thread_results.items():
        output += "{}\tID{}\t\t{}\n".format(id, thread[THREAD_ID], thread[THREAD_STATUS])
    return output

#connector function for Netmiko device connection
def connector(id, results, thread_log, log_lock, queue):
    global success_count
    global fail_count

    #outer catch block - ensures threads are killed on encountered issue
    try:
        while True:
            #reset temp variables for each thread run
            output = ''
            tempOutput = ''

            #obtain thread queue
            device = queue.get()
            if verbose:
                with print_lock:
                    print("Thread ID{}: Initiating a connection to host {}".format(id, device['host']))

            # build the netmiko valid dict
            device_dict =  {
                'host': device['host'],
                'username': device['username'],
                'password': device['password'],
                'device_type': device['device_type'],
                'secret': device['secret'],
            }
            
            #output reachability check
            #def process_logging(thread, level, host, msg, thread_log)
            if verbose:
                with print_lock:
                    print("Thread ID{}: Checking reachability to host {}".format(id, device['host']))
            response = ping(device['host'], timeout=3, unit='ms')
            if response:
                msg = "Connectivity tests to host were successful ({}ms)".format(round(response, 2))
                if verbose:
                    with print_lock:
                        print("Thread ID{}: {}".format(id, msg))
                with log_lock:
                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "INFO", device['host'], msg))
            else:
                msg = "Connectivity tests to host have failed"
                if verbose:
                    with print_lock:
                        print("Thread ID{}: : Host '{}' Connectivity tests have failed.".format(id, device['host']))
                with log_lock:
                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "INFO", device['host'], msg))

            try:
                #start netmiko work
                conn = ConnectHandler(**device_dict)

                #enter enable mode if secret has been set
                if device_dict['secret'] != '':
                    msg = "Entering enable mode"
                    if verbose:
                        with print_lock:
                            print("Thread ID{}: {} for host '{}'.".format(id, msg, device['host']))
                        with log_lock:
                            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "INFO", device['host'], msg))
                    try:
                        conn.enable()
                    except ValueError:
                        msg = "Failed to enter enable mode for host"
                        with print_lock:
                            print("Thread ID{}: ERROR:  {} on host '{}' [Check the provided passphrase].".format(id, msg, device['host']))
                        with log_lock:
                            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "WARNING", device['host'], msg))

                if verbose:
                    with print_lock:
                        print("Thread ID{}: Issuing command blocks for host '{}'.".format(id, device['host']))
                
                #obtain device prompt/hostname output
                prompt = conn.find_prompt()
                
                #iterate through command blocks
                for block in device['commands']:
                    block_type = block[BLOCK_TYPE]

                    if "read_block" in block_type:
                        for cmd in block[BLOCK_CLI]:
                            msg = "Sending command '{}'".format(cmd)
                            if verbose:
                                print("Thread ID{}: {}".format(id, msg))
                            with log_lock:
                                thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "INFO", device['host'], msg))
                            tempOutput += prompt
                            tempOutput += cmd
                            tempOutput += "\n"
                            feedback = conn.send_command_expect(cmd, delay_factor=4)
                            tempOutput += feedback
                            if "Invalid input" in feedback or "Unknown command" in feedback:
                                msg = "Error issuing command '{}'. Please check command synxtax and platform support.".format(cmd)
                                if verbose:
                                    print("Thread ID{}: ERROR: {} to host '{}' [Invalid command or priviledge issue].".format(id, msg, device['host']))  
                                with log_lock:
                                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "ERROR", device['host'], msg))
                        output += tempOutput
                        tempOutput = "" #reset the temp output var

                    if "write_block" in block_type:
                        msg = "Issuing write_block: {}".format(str(block[BLOCK_CLI]))
                        with log_lock:
                            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "INFO", device['host'], msg))
                        tempOutput += "\nIssuing write_block: " + str(block[BLOCK_CLI])
                        tempOutput += "\n"
                        feedback = conn.send_config_set(block[BLOCK_CLI])
                        tempOutput += feedback 
                        tempOutput += "\n"
                        if "Invalid input" in feedback or "Unknown command" in feedback:
                            msg = "Error issuing command block to host. Please check command synxtax and platform support."
                            if verbose:
                                print("Thread ID{}: ERROR: {} to host '{}'.\n{}".format(id, msg, device['host'], block[BLOCK_CLI]))
                            with log_lock:
                                thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "ERROR", device['host'], msg))
                        output += tempOutput
                        tempOutput = "" #reset the temp output var
                        
                    if "save" in block_type:
                        tempOutput += "Saving configuration: " + str(block[BLOCK_CLI])
                        feedback = conn.save_config()
                        tempOutput += feedback
                        tempOutput += "\n"                        
                        output += tempOutput
                        tempOutput = "" #reset the temp output var
                        msg = "Configuration save completed."
                        with log_lock:
                            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(), "ID"+str(id), "INFO", device['host'], msg))

                #each thread writes to a different file - write-lock not required
                output_file = device['output_dir'] + '\\' + append_datetime(device_dict['host']) + '.log'
                write_file(output, output_file)

                with print_lock:
                    msg = "File write for host '{}' successful.".format(device_dict['host'])
                    if verbose:
                        print("Thread ID{}: {}".format(id, msg))
                    with log_lock:
                        thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"ID"+str(id), "INFO", device['host'], msg))

                output_file = "" #reset output file location
                success_count += 1 #increment thread success count
                results[device_dict['host']] = ("Success", id, "Thread successfully completed.") #update thread result for host
                msg = "Thread tasks have been successfully completed"
                with log_lock:
                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"ID"+str(id), "INFO", device['host'], msg))

                #close thread once finished
                queue.task_done()

            except NetMikoTimeoutException:
                temp_status = "Netmiko Connection Timeout Exception [No response from host on connection attempt]"
                if verbose:
                    temp_output = "Thread ID{}: ERROR: Netmiko connection timeout for host '{}'.".format(id, device['host'])
                    with print_lock:
                        print(temp_output)
                queue.task_done()
                fail_count += 1 #increment thread fail count
                results[device_dict['host']] = ("Fail", id, temp_status) #update thread result for host
                with log_lock:
                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"ID"+str(id), "ERROR", device['host'], temp_status))
                continue
            except NetMikoAuthenticationException:
                temp_status = "Netmiko Authentication Exception [Provided credentials are invalid or incorrect]"
                if verbose:
                    temp_output = "Thread ID{}: ERROR: Netmiko authentication error for host '{}'.".format(id, device['host'])
                    with print_lock:
                         print(temp_output)
                queue.task_done()
                fail_count += 1 #increment thread fail count
                results[device_dict['host']] = ("Fail", id, temp_status) #update thread result for host
                with log_lock:
                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"ID"+str(id), "ERROR", device['host'], temp_status))
            except IOError:
                temp_status = "Netmiko IOError Exception [Thread failed during command send process]"
                if verbose:
                    temp_output = "Thread ID{}: ERROR: IOError for host '{}'.".format(id, device['host'])
                    temp_output_02 = "Thread ID{}: INFO: Try changing protocol to Telnet for host '{}'.".format(id, device['host'])
                    with print_lock:
                        print(temp_output)
                        print(temp_output_02)
                queue.task_done()
                fail_count += 1 #increment thread fail count
                results[device_dict['host']] = ("Fail", id, temp_status) #update thread result for host
                with log_lock:
                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"ID"+str(id), "ERROR", device['host'], temp_status))
            except Exception as err:
                temp_status = "General Exception [Unknown error occured during thread execution]"
                if verbose:
                    temp_output = "Thread ID{}: ERROR: General exception occured for host '{}'.".format(id, device['host'])
                with print_lock:
                    print(temp_output)
                queue.task_done()
                fail_count += 1 #increment thread fail count
                results[device_dict['host']] = ("Fail", id, temp_status) #update thread result for host
                with log_lock:
                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"ID"+str(id), "ERROR", device['host'], temp_status))

    except Exception as err:
        temp_status = "General Exception [Unknown error occured during thread execution]"
        if verbose:
            temp_output = "Thread ID{}: ERROR: General exception occured for host '{}'.".format(id, device['host'])
            with print_lock:
                print(temp_output)
        queue.task_done()
        fail_count += 1 #increment thread fail count
        results[device_dict['host']] = ("Fail", id, temp_status) #update thread result for host
        with log_lock:
            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"ID"+str(id), "ERROR", device['host'], temp_status))

    #task completed
    queue.task_done()

def main():
    #regex
    comment = r'^#.*'
    cisco_comment = r'^!.*'
    newline = r'^\s*$'
    empty = r'^\s*$'
    contains_data = re.compile(r'^[\w.\-_@]+$')
    thread_results = {}
    thread_log = []
    
    #define a lock the logging variable
    log_lock = Lock()

    #outer try/except block to catch premature script kill
    try:

        #print script header
        print_header()

        #start application timer
        start=datetime.now()

        #verify passed argument validity
        args = parse_args(thread_log)

        #check for output verbosity
        global verbose
        if args.verbose:
            print("STATUS: Verbose output enabled.")
            verbose = True

        #temp holder for devices
        devices = {}
        command_files = {}
        account =   {
                        'username': '',
                        'password': '',
                        'secret': '',
                    }

        #check if --login flag provided - prompt for dynamic account details
        global dynamic_account

        #flag to check if a dynamic account has been provided
        account_present = False

        #Warn user about save flag superseding all other provided commands
        msg = "Save flag passed via CLI. Only configurational save will be executed on device/s."
        if args.save:
            print('WARNING: {}'.format(msg))
        
            #Update log file
            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "WARNING", "--", msg))

        #Check for dynamic login details
        if args.login:
            msg = "Dynamic account provided for login across all devices."
            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
            dynamic_account = True
            print("\nPROMPT: Please enter generic account details.")
            print("INFO: This account will be used for login across all hosts.\n")
            account = get_account()
            account_present = True

        #determine account details via input file or args
        line_count = 0
        if args.list_device:
            device_file = read_file(args.list_device)
            
            #Update log file
            msg = "Device list [{}] provided as input.".format(args.list_device)
            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))

            for line in device_file:
                line_count += 1
                #check for comment of newline and skip where applicable
                is_comment = re.match(comment, line)
                is_newline = re.match(newline, line)
                if is_comment or is_newline:
                    continue
                #line contains content - process data.
                else:
                    temp_list = line.split(';')
                    #self, name, user, password, device_type, commands
                    device = Device(
                        name='', 
                        user='', 
                        password='', 
                        secret='', 
                        device_type='cisco_ios', 
                        commands=[]
                    )
                    for attr in temp_list:
                        item = attr.split(':')
                        #skip if attr is blank
                        if re.match(empty, item[0]):
                            msg = 'Missing attribute around \'{}{}\' in line {}'.format(';', item[1], line_count)
                            print("ERROR: ",msg)
                            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "ERROR", "--", msg))
                            continue
                        else:
                            if re.match(contains_data, item[0]) and len(item) >= 2:
                                #check if class contains the provided attribute
                                if hasattr(device, item[0]):
                                    if not re.match(empty, item[1]):
                                        device.update_attribute(item[0], item[1])
                                    else:
                                        #blank entry in current attribute - skip
                                        continue
                                else:
                                    msg = 'Invalid attribute {} at line {}'.format(item[0], line_count)
                                    print("ERROR: ",msg)
                                    thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "ERROR", "--", msg))
                                    break
                            else:
                                msg = "Blank attr located on line {}".format(line_count)
                                print("ERROR: ",msg)
                                thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "ERROR", "--", msg))
                                break

                    #Unpack command files into structured format
                    in_file = read_file(device.commands[0])
                    temp_arr = []
                    for cmd in in_file:
                        if check_cisco_command(cmd):
                            temp_arr.append(cmd)

                    #reformat commands into structured blocks
                    cmd_blocks = parse_commands(temp_arr)
                    device.commands = cmd_blocks

                    # --login flag enabled - configure all devices with dynamic account details
                    if dynamic_account:
                        device.username = account['username']
                        device.password = account['password']
                        device.secret = account['secret']
                    else:
                        #check if device has been provided with valid account details
                        empty_username = re.match(empty, device.username)
                        empty_password = re.match(empty, device.password)
                        #empty fields found - prompt for generic host credentials
                        if empty_username or empty_password:
                            if account_present:
                                device.username = account['username']
                                device.password = account['password']
                                device.secret = account['secret']
                            else:
                                print("\nPROMPT: Please enter generic account details.")
                                print("WARNING: This account will be used for login across all hosts.\n")
                                account = get_account()
                                device.username = account['username']
                                device.password = account['password']
                                device.secret = account['secret']
                                account_present = True

                    #Verify all device elements are within acceptable bounds
                    if device.valid_check():
                        msg = "Host {} on line {} successfully validated.".format(device.hostname, line_count)
                        if verbose:
                            print("INFO: {}".format(msg))
                        thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
                        devices[line_count] = device
                    else:
                        msg = "Insufficient host details located on line {}. Skipping entry.".format(line_count)
                        if verbose:
                            print("ERROR: {}".format(msg))
                        thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "ERROR", "--", msg))

        else:
            #check for valid device
            if not args.device:
                print('ERROR: No hosts provided to config-runner. Please provide via args or "list_device" input.')
                sys.exit(1) 
            
            #check for valid login details
            if account_present:
                device = Device(
                                    name = args.device, 
                                    user = account['username'], 
                                    password = account['password'], 
                                    secret = account['secret'], 
                                    device_type = 'cisco_ios', 
                                    commands = [],
                                )
                devices[args.device] = device

            #valid account not found - prompt for login details
            else:    
                print("\nEnter connection details for host '{}'".format(args.device))
                account = get_account()
                device = Device(
                                    name = args.device, 
                                    user = account['username'], 
                                    password = account['password'], 
                                    secret = account['secret'], 
                                    device_type = 'cisco_ios', 
                                    commands = [],
                                )
                devices[args.device] = device

            #[NO DEVICE LIST PREFERENCE #1] Save command pushed to device
            if args.save:
                msg = "Save flag passed via args. No other commands will be executed across devices."
                thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
                for device in devices.keys():
                    save_flag = []
                    save_flag.append(("save", ""))
                    devices[device].commands = save_flag

            #[NO DEVICE LIST PREFERENCE #2] Single CLI command pushed to device
            elif args.command:
                msg = "Command passed via args. Single input [Read mode] will be executed across devices."
                thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
            
                #issue same command to all provided devices
                temp_arr = []
                temp_arr.append(args.command)
                for device in devices.keys():
                    if check_cisco_command(args.command):
                        read_block = []
                        read_block.append(("read_block", temp_arr))
                        devices[device].commands = read_block

            #[NO DEVICE LIST PREFERENCE #3] CLI commands in file pushed to device
            elif args.list_command:
                msg = "Command list passed via args. Same input file will be executed across all devices."
                thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
                for device in devices.keys():
                    in_file = read_file(args.list_command)
                    temp_arr = []
                    for cmd in in_file:
                        if check_cisco_command(cmd):
                            temp_arr.append(cmd)

                    #obtain read/write command blocks
                    cmd_blocks = parse_commands(temp_arr)
                    devices[device].commands = cmd_blocks

        msg = "Initiating netmiko process threads."
        print("\nINFO: {}".format(msg))
        thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))

        #prevent start up of more threads than provided devices
        thread_count = int(args.threads)
        dev_count = len(devices.items())
        if dev_count < thread_count:
            thread_count = dev_count
            msg = 'Defined thread count [{}] exceeeds total devices [{}]. Adjusting thread count to match.'.format(thread_count, dev_count)
            if verbose:
                print("\nINFO: {}".format(msg))
            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
        
        #initiate threads        
        for id in range(thread_count):
            #create the thread and consume the connector function
            thread = threading.Thread(target=connector, args=(id, thread_results, thread_log, log_lock, thread_queue,))
            thread.daemon = True
            thread.start()
            msg = "Started Thread ID{}".format(id)
            thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))

        print("INFO: Netmiko process threads are running. Please wait for completion...")

        #add all defined/valid hosts to the thread queue
        for key in devices.keys():
            #define our host in the required Netmiko format
            net_connect = {
                "device_type" : devices[key].device_type,
                'host' : devices[key].hostname,
                'username' : devices[key].username,
                'password' : devices[key].password,
                'secret' : devices[key].secret,
                'commands': devices[key].commands,
                'output_dir': args.output
            }

            #send host details to the queue
            thread_queue.put(net_connect)

        # wait for all threads to return complete
        thread_queue.join()

        msg = "Netmiko process threads have completed."
        print("INFO: {}".format(msg))
        thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))

        #compile summary stats        
        status = {
            "start_time": start,
            "total_thread": len(devices.keys()),
            "success_thread": success_count,
            "fail_thread": fail_count,
            "fallback_thread": None,
            "log_location": args.output,
            "output_location": args.output
        }

        #print summary stats
        print(get_execute_summary(status))
        
        #print thread results
        print(get_thread_results(thread_results))
        
        #insert runtime into log file
        msg = "Total runtime: {}".format(datetime.now()-start)
        thread_log.append('"{}","{}","{}","{}","{}"'.format(datetime.now(),"SYSTEM", "INFO", "--", msg))
        
        #output log file
        output_file = args.output + '\\' + append_datetime("cfgRun_execStatus") + '.csv'
        write_file_array(thread_log, output_file)
        
    except KeyboardInterrupt:
        print("\nBREAK: Exiting program.")
        #kill all running threads
        sys.exit(1) 

if __name__ == '__main__':
    main()