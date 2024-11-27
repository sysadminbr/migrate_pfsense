# Migrate pfSense to OPNSense Script
Script to Quickly Migrate From pfSense firewall to OPNSense With Easy

## Requirements
- Install and basic setup of the target firewall (opnsense)  
- The interfaces names in the new Firewall *MUST MATCH* the names from the old firewall (eg.: LAN, WAN, WIFI, DMZ, MY_POKER_VLAN)    
- In all firewall rules or RDR (nat) must be a comment.

## Usage
1- Download this project as .zip or clone it with git clone.  
2- Download pfsense config as a backup (menu diagnostics -> backup & restore), rename the downloaded file to pfsense.xml and put it in the same folder as migrate_pfsense.py file.  
3- Edit the file .env to reflect your opnsense root credentals. example:  
```  
OPSENSE_URL       = 'https://192.168.100.156'
OPNSENSE_USER     = 'root'
OPNSENSE_PASSWORD = 'root'  
```  
4- Install python3 and the project dependencies
```  
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```  

7- Run the script and watch the screen for processing steps.  
```  
python migrate_pfsense.py
```  
8- That's it! Hope it help you too.



## Limitations  
At the time, it's possible to migrate without problems:  
- Aliases
- Firewall Rules (both interface rules and floating rules)
- NAT rules (port forwarding)
- OpenVPN servers (targeted as legacy servers)
- DHCPD interface config
- DHCPD static leases
- Certificate Authorities and Certificates
- Static Routes
- Backend Authentication Servers (LDAP)
- The static routes are imported with a Null Gateway. It's up to you to edit them and associate the right gateway.

What's not possible to migrate yet:  
- Outbound NAT
- 1:1 NAT
- Certificate Revocation List
- Local users and groups
- Schedulers
- Traffic Shaper
- Captive Portal
- PPPoE
- IPSec
- Unbound
- HAProxy
- System DNS
- Hostname and Domain
- Wireguard


