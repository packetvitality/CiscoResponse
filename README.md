# SMIThreat
This is a Python3 script to aid in responding to Cisco Smart Install SMI misuse. Threat is covered in detailed by US-CERT alert TA18-106A.

A Cisco feature called Smart Install (SMI) can be exploited to steal configurations and lead to re-routed network traffic. SNMP can also be weaponized as well but will not be covered here. 
Cisco became aware of the situation in 2017 and published an advisory which can be found [here](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi). In 2018 US-CERT released a well detailed alert named TA18-106A which can be found [here](https://www.us-cert.gov/ncas/alerts/TA18-106A). Both advisories contain a wealth of information to effectively identify and respond to the threat. According TA18-106A: “Targets are primarily government and private-sector organizations, critical infrastructure providers, and the Internet service providers (ISPs) supporting these sectors.”
