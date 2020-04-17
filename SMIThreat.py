from netmiko import ConnectHandler
import netmiko
import getpass
import os
import re
import json
import argparse
import sys

class SMIThreat:
    """
    Helps with responding to Cisco SMI exploitation as detailed in US Cert alert 'TA18-106A'
    Can check for the vulnerable service,\n
    identify connections / ioc's,\n
    disable the service.
    """
    def __init__(self, device_list_input, username, password):
        self.username = username
        self.password = password
        self.vulnerable_devices = set()
        self.remediated_devices = set()
        self.device_list_input = device_list_input
        self.device_list = set()
        self._get_device_list()
        self.guid = 1
        self.smi_connections = {}
        self.smi_all_remote_ips = set()
        self.smi_estab_remote_ips = set()

    def _get_device_list(self):
        """
        Checks if the input is a file or a string
        Opens file and adds devices to the set; or
        Adds the string to the set
        """
        if isinstance(self.device_list_input, set):
            for i in self.device_list_input:
                self.device_list.add(i)

        elif os.path.isfile(self.device_list_input):
            with open(self.device_list_input) as ips:
                for ip in ips:
                    self.device_list.add(ip)
        
        elif isinstance(self.device_list_input, str):
            self.device_list.add(self.device_list_input)

    def _set_conn_settings(self, ip):
        """
        Connection settings for cisco ios device.
        """
        conn_setting = {
            'device_type':'cisco_ios',
            'ip':ip,
            'username':self.username,
            'password':self.password,
            'secret':self.password,
        }
        return conn_setting

    def _output_to_file(self, out_file, data, comment=False):
        """
        Accepts iterable data\n
        Outputs to supplied file, will overwrite\n
        Dictionaries are output as JSON\n
        Otherwise, data is output into file delmited by newlines
        """
        if data: #Ensure there is something to valid to work with
            #Working with dictionaries, currently returned from get_sessions
            if type(data) is dict:
                #Force file extension of JSON
                base_filename = out_file.split(".")[0]
                json_filename = base_filename + ".json"
                #Save JSON data to file with indented format
                with open(json_filename, 'w') as file:
                    myjson = json.dumps(data, indent=4)
                    file.write(myjson)
                print("Session information saved to: \"{}\"".format(json_filename))
            
            #Working with the rest of the data
            elif comment: #Store as a CSV with the comment
                with open(out_file, 'a') as file:
                    for d in data:
                        my_join = (d,comment)
                        commented_line = ",".join(my_join)
                        file.write(commented_line + "\n")
                    print("Results stored in: \"{}\"".format(out_file))
            else:
                with open(out_file, 'a') as file:
                    for d in data:
                        file.write(d + "\n")
                    print("Results stored in: \"{}\"".format(out_file))

    def check_service(self):
        """
        Checks device in the list to identifies Smart install running as a client
        Returns a set of vulnerable devices. 
        """
        print("Checking if SMI is enabled and running as a client. . .\n")
        for i in self.device_list:
            #Settings for connection handler
            ip = i.rstrip() #Remove whitespace
            conn_setting = self._set_conn_settings(ip)
            try:
                #Establish Connection
                net_connect = ConnectHandler(**conn_setting)
                send = net_connect.send_command
                net_connect.enable()
                #Send commands & look for expected values
                print("{} --> Connected".format(ip))
                result = send("show vstack config | inc Role") #Sending enable commands
                if "client" and "enabled" in result.lower(): #Vulnerable criteria
                    print("{} -Vulnerable- {}".format(ip,result))
                    self.vulnerable_devices.add(ip)
                elif "invalid input" in result.lower(): #Device did not accept the command
                    print("{} - Appears the device does not support SMI.".format(ip))
                else:
                    print("{} -Not Vulnerable- {}".format(ip,result))

                #Close connection
                net_connect.disconnect()
            
            #General error, I think due to the device not responding
            except OSError:
                print("{} - Connection Error!".format(ip))
                pass
            
            #Login Failures
            except netmiko.ssh_exception.NetMikoAuthenticationException:
                print("{} - Failed login attempt!".format(ip))
                pass
            
            #Connection timeout
            except netmiko.ssh_exception.NetMikoTimeoutException:
                print("{} - Unable to connect to device!".format(ip))
                pass
        
        if self.vulnerable_devices:
            return self.vulnerable_devices
        else:
            return False

    def get_sessions(self):
        """
        Pulls the tcp connections from the device list
        Identifies connections over port 4786
        Returns a dictionary if those connections exist
        """
        port_check = "4786" #Careful what is used here if not 4786. If it is a number that could be used in an IP address, could get false positives. 
        if self.device_list:
            print("Checking port {} sessions. . .\n".format(port_check))
            for i in self.device_list:
                #Settings for connection handler
                ip = i.rstrip() #Remove whitespace
                conn_setting = self._set_conn_settings(ip)
                try:
                    #Establish Connection
                    net_connect = ConnectHandler(**conn_setting)
                    send = net_connect.send_command
                    net_connect.enable()
                    #Send commands & look for expected values
                    print("{} --> Connected".format(ip))
                    result = send("show tcp brief all") #sending enable commands
                    result_newline = result.split("\n") #Format text based on newline character
                    for i in result_newline:
                        result_csv = re.sub("\s+", ",", i.strip()) #Replace whitespace with a comma
                        if port_check in result_csv: #Look for connections over the port
                            tcb = result_csv.split(",")[0]
                            local_address = result_csv.split(",")[1]
                            foreign_address = result_csv.split(",")[2]
                            state = result_csv.split(",")[3]
                            self.smi_connections[self.guid] = { #Store results in a dictionary using a unique identifier
                                "TCB":tcb,
                                "local_address": local_address,
                                "foreign_address": foreign_address,
                                "state": state
                            }
                            print(json.dumps(self.smi_connections[self.guid], indent=4) + "\n")
                            self.guid += 1 #Increment unique identifier
                    
                    #Close connection
                    net_connect.disconnect()
                
                #General error, I think due to the device not responding
                except OSError:
                    print("{} - Connection Error!\n".format(ip))
                    pass
                
                #Login Failures
                except netmiko.ssh_exception.NetMikoAuthenticationException:
                    print("{} - Failed login attempt!\n".format(ip))
                    pass
                
                #Connection timeout
                except netmiko.ssh_exception.NetMikoTimeoutException:
                    print("{} - Unable to connect to device!\n".format(ip))
                    pass

            if self.smi_connections:
                return self.smi_connections
            else:
                return False

        else:
            print("Attempted to check sessions, but there were no devices supplied.")
            return False
    
    def disable_service(self):
        """
        Disables the SMI service on the provided devices.
        Returns a set of remediated devices.
        """
        print("\nDisabling SMI. . .\n")
        if self.device_list:
            for i in self.device_list:
                #Settings for connection handler
                ip = i.rstrip() #Remove whitespace
                conn_setting = self._set_conn_settings(ip)
                try:
                    #Establish Connection
                    net_connect = ConnectHandler(**conn_setting)
                    net_connect.enable() #Ensure we are in enable mode
                    #Send commands & look for expected values
                    result = net_connect.send_config_set("no vstack config")
                    print("{} --> Connected".format(ip))
                    if "invalid input" in result.lower():
                        print("{} - Appears the device does not support SMI.\n".format(ip))
                    else:
                        print("{}\n".format(result))
                        self.remediated_devices.add(ip)
                    #Close connection
                    net_connect.disconnect()
                
                #General error, I think due to the device not responding
                except OSError:
                    print("{} - Connection Error!\n".format(ip))
                    pass
                
                #Login Failures
                except netmiko.ssh_exception.NetMikoAuthenticationException:
                    print("{} - Failed login attempt!\n".format(ip))
                    pass
                
                #Connection timeout
                except netmiko.ssh_exception.NetMikoTimeoutException:
                    print("{} - Unable to connect to device!\n".format(ip))
                    pass
            if self.remediated_devices:
                return self.remediated_devices
            else:
                 return False

        else:
            print("There were no devices supplied.")
            return False

def main():
    """
    Command line usability.\n
    Details the arguments, logic flow, error checking etc.
    """
    parser = argparse.ArgumentParser(prog='PROG',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=
    '''
    This is a script to aid in responding to Cisco Smart Install SMI misuse. Threat is covered in detailed by US-CERT alert TA18-106A.
    This script can: check if a device is vulnerable, pull tcp sessions related to SMI, and and/or disable SMI.
    These options can be used together. For example, you can specify -cd to check devices and disable the vulnerable devices. 

    Example Usage:
    --------------------------------
    Check if SMI is running on one device:
    python.exe SMIThreat.py -H 10.1.1.20 -c

    Check if SMI is running on all devices in the provided newline delimited file:
    python.exe SMIThreat.py -f "/path/to/file" -c

    Disable SMI on all devices in the provided file:
    python.exe SMIThreat.py -f "/path/to/file" -d

    Check if SMI is running on all devices in the provided newline delimited file, disable vulnerable devices:
    python.exe SMIThreat.py -f "/path/to/file" -cd

    Pull TCP sessions matching the SMI port:
    python.exe SMIThreat.py -H myswitch.domain.internal -s

    Check if SMI is running on all devices in the provided newline delimited file, pull the TCP sessions matching the SMI port (4789):
    python.exe SMIThreat.py -f "/path/to/file" -cs

    Output Example 1:
    python.exe SMIThreat.py -f "/path/to/file" -cdo "/path/to/file"
    
    Output Example 2:
    python.exe SMIThreat.py -f "/path/to/file" -csdo "/path/to/file"
    --------------------------------
    ''')

    #Command line Arguements
    #Required Arguements
    parser.add_argument('--host', '-H', help="Must provide an individual ip/hostname.")
    parser.add_argument('--file', '-f', help="New line delimited file of ips/hostnames.")
    #Optional Arguements
    parser.add_argument('--username', '-u', help='Username for logging into devices. Default is the currently logged in user.', default=getpass.getuser())
    parser.add_argument('--output', '-o', help='Output file. Be sure to use quotes like "path/to/file". If the sessions option is used, the output will be stored in JSON file.')
    #Optional Arguements that do not need parameters
    parser.add_argument('--check', '-c', help='*IDENTIFICATION* Check devices to see if SMI services is running a client. Can feed vulnerable devices into the "sessions" or "disable" options.', action='store_true')
    parser.add_argument('--sessions', '-s', help='*CONTAINMENT / INTELLIGENCE GATHERING* Pulls the tcp sessions for the provided port 4786.', action='store_true')
    parser.add_argument('--disable', '-d', help='*ERADICATION* Disables the SMI service on the provided devices.', action='store_true')

    args = parser.parse_args()

    #Validating command line arguements
    if not args.host and not args.file:
        parser.error('Please provide input data with the -f or -H options')

    if args.host and args.file:
        parser.error("Must provide a host or a file, not both.")

    if not args.check and not args.sessions and not args.disable:
        parser.error("Must provide at least one of the following options: -c, -s, -d")

    if args.host:
        device_list_input = args.host

    if args.file:
        if not os.path.isfile(args.file):
            parser.error("\nCould not locate a file named: \"{}\" \nDouble check the file path is correct and put it in quotes.".format(args.file))
        else:
            device_list_input = args.file

    if args.output:
        out_file = args.output
        if os.path.isfile(out_file):
            os.remove(out_file)

    #Credentials
    username = args.username
    print("Attempting to log into device(s) with user: \"{}\"".format(username))
    password = getpass.getpass()

    #Instantiate Object
    SMI = SMIThreat(device_list_input, username, password)

    #Check which options have been provided
    if args.check and args.sessions and args.disable: #The vulnerable devices from check are fed into sessions and disable
        vuln_devices = SMI.check_service()
        SMI = SMIThreat(vuln_devices, username, password)
        sessions = SMI.get_sessions()
        remediated_devices = SMI.disable_service()
        if args.output:
            write_results = SMI._output_to_file
            write_results(out_file, remediated_devices, comment="Remediated")
            #Only append vulnerable devices the file if they have not been remediated.
            for device in vuln_devices:
                if device not in remediated_devices:
                    write_results(out_file, vuln_devices, comment="Vulnerable")
            write_results(out_file, sessions)

    
    elif args.check and args.sessions: #The vulnerable devices from check are fed into sessions
        vuln_devices = SMI.check_service()
        SMI = SMIThreat(vuln_devices, username, password)
        sessions = SMI.get_sessions()
        if args.output:
            write_results = SMI._output_to_file
            write_results(out_file, vuln_devices)
            write_results(out_file, sessions)

    elif args.check and args.disable: #The vulnerable devices from check are fed into disable
        vuln_devices = SMI.check_service()
        SMI = SMIThreat(vuln_devices, username, password)
        remediated_devices = SMI.disable_service()
        if args.output:
            write_results = SMI._output_to_file
            write_results(out_file, remediated_devices, comment="Remediated")
            #Only append vulnerable devices the file if they have not been remediated.
            for device in vuln_devices:
                if device not in remediated_devices:
                    write_results(out_file, vuln_devices, comment="Vulnerable")
    
    elif args.sessions and args.disable: #Sessions and disable provided. Pull the sessions then disable service.
        sessions = SMI.get_sessions()
        remediated_devices = SMI.disable_service()
        if args.output:
            SMI._output_to_file(out_file, remediated_devices)
            SMI._output_to_file(out_file, sessions)

    elif args.check: #Only check is provided
        vuln_devices = SMI.check_service()
        if args.output:
            SMI._output_to_file(out_file, vuln_devices)
    
    elif args.sessions: #Only sessions is provided
        sessions = SMI.get_sessions()
        if args.output:
            SMI._output_to_file(out_file, sessions)

    elif args.disable: #Only disable is provided
        remediated_devices = SMI.disable_service()
        if args.output:
            SMI._output_to_file(out_file, remediated_devices)

def for_coders():
    """
    If you find a need to tweak the code,\n
    intergrate the data into your own workflows,\n
    etc. . .\n
    This function is for you! <3
    """

    #Set Credentials. Prefer getpass but you can hardcode these if needed.
    username = getpass.getuser() #Currently logged in user
    password = getpass.getpass() #Prompt user for password

    #Specify input file. Must be a newline delimeted list of ips or hostnames
    device_list_input = "path/to/file"
    
    #Instantiate the object
    SMI = SMIThreat(device_list_input, username, password)

    ###IDENTIFICATION
    vuln_devices = SMI.check_service()
    print(vuln_devices)

    ###CONTAINMENT / INTELLIGENCE GATHERING
    # SMI = SMIThreat(vuln_devices, username, password)
    # sessions = SMI.get_sessions()
    # print(sessions)

    ###ERADICATION
        #Made to work with the check_service() function
        #Feed in the vuln_devices variable identified above as a parameter
        #Will also accept a file
    # SMI = SMIThreat(vuln_devices, username, password)
    # remediated_services = SMI.disable_service()
    # print(remediated_services)

if __name__ == '__main__':
    main()
    
#for_coders()
