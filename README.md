# CiscoResponse
This is a Python3 script initially created to aid in responding to Cisco Smart Install SMI misuse. Threat is covered in detailed by US-CERT alert TA18-106A. 

As other use cases are found, they will also be added. For example CVE-2023-20198 as documented [here](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z) can be checked by using the custom command (-x) option. 

A Cisco feature called Smart Install (SMI) can be exploited to steal configurations and lead to re-routed network traffic. SNMP can also be weaponized as well but will not be covered here. 
Cisco became aware of the situation in 2017 and published an advisory which can be found [here](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi). In 2018 US-CERT released a well detailed alert named TA18-106A which can be found [here](https://www.us-cert.gov/ncas/alerts/TA18-106A). Both advisories contain a wealth of information to effectively identify and respond to the threat.

To get started, download the repository. 

The script is dependant on the Netmiko library. Netmiko can be installed with the provided requirements.txt file.    
    
    pip install -r requirements.txt

The script can: 
Check if a device is vulnerable, 
Pull tcp sessions related to SMI, 
and/or disable SMI.

These options can be used together. For example, you can specify -cd to check devices and disable the vulnerable devices. 
    
## Example Usage
### Check if SMI is running on one device:
    python.exe CiscoResponse.py -H 10.1.1.20 -c

### Check if SMI is running on all devices in the provided newline delimited file:
    python.exe CiscoResponse.py -f "/path/to/file" -c

### Disable SMI on all devices in the provided file:
    python.exe CiscoResponse.py -f "/path/to/file" -d

### Check if SMI is running on all devices in the provided newline delimited file, disable vulnerable devices:
    python.exe CiscoResponse.py -f "/path/to/file" -cd

### Pull TCP sessions matching the SMI port:
    python.exe CiscoResponse.py -H myswitch.domain.internal -s

### Check if SMI is running on all devices in the provided newline delimited file, pull the TCP sessions matching the SMI port (4789):
    python.exe CiscoResponse.py -f "/path/to/file" -cs

### Output Example 1:
    python.exe CiscoResponse.py -f "/path/to/file" -cdo "/path/to/file"

### Output Example 2:
    python.exe CiscoResponse.py -f "/path/to/file" -csdo "/path/to/file"

### Custom Command Example:
    python.exe CiscoResponse.py -x -f "cisco_devices.txt" -o "results.json"
    After entering your credentials, issue a command in "quotes". For example:
    "show running-config | include ip http server|secure|active"
- - - -
Tested with Python 3.6.5.

Hope this is helpful! If you experience any issues let me know so I can try to resolve them.
