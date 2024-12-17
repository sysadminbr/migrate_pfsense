#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import sys
from pathlib import Path
import json
import base64
import urllib3
import requests
import bs4 as BeautifulSoup
import xml.etree.ElementTree as ET
import re
from dotenv import load_dotenv
from firewall import OPNsense
from functions import extract_rule_attributes, extract_nat_rule_attributes, \
     get_pfsense_config, extract_dhcp_attributes, get_static_dhcp_leases
import pdb

PFSENSE_CONFIG_FILE = "pfsense.xml"

if __name__ == '__main__':
    # disable self-signed certificates warnings
    urllib3.disable_warnings()

    # work on script dir (cwd)
    os.chdir(Path(__file__).parent)

    # load user/pass from .env
    load_dotenv()
    
    # connect on opnsense
    opn = OPNsense(
        url=os.environ.get("OPSENSE_URL"), 
        user=os.environ.get("OPNSENSE_USER"), 
        password=os.environ.get("OPNSENSE_PASSWORD") 
    )
    
    
    # --------------------------------------------------
    # Load pfSense config xml
    #--------------------------------------------------
    pfsense = get_pfsense_config(PFSENSE_CONFIG_FILE)
    

    # --------------------------------------------------
    # Migrating static routes
    #--------------------------------------------------
    # check if routes already exists, otherwise import it.
    # it is going to import static routes with an empty gateway, so you can then adjust accordingly.
    opn_routes = opn.get_routes()
    staticroutes = pfsense.find("staticroutes")
    for route in staticroutes.findall("route"):
        network = route.find("network").text
        description = route.find("descr").text
        if opn.route_exists(network):
            print(f'route already registered on target firewall. skipping it')
            continue
        else:
            req = opn.add_route(network=network, gateway="Null4", description=description)

    
    # --------------------------------------------------
    # Migrating Certificate Authorities
    #--------------------------------------------------
    # an interesting one. Load authorities then the certificates.
    # OPNsense 24.7_7 are able to import certificates and automatically associate with previously imported authorities.
    migrated_authorities = {}
    authorities = pfsense.findall("ca")
    for authority in authorities:
        crt_name = authority.find("descr").text
        migrated_authorities[crt_name] = {}
        for element in authority:
            migrated_authorities[crt_name][element.tag] = element.text if element.tag not in ('crt', 'prv') else ''
        crt_encoded = authority.find("crt").text
        crt = base64.b64decode(crt_encoded).decode()
        key_encoded = authority.find("prv").text if authority.find("prv") is not None else None
        key = base64.b64decode(key_encoded).decode() if key_encoded is not None else None
        refid = authority.find("refid").text
        if not opn.ca_certificate_exists(crt_name):
            opn.import_ca_certificate(crt_name, crt, key)
        else:
            print(f'ca {crt_name} already registered. skipping it.')


    # --------------------------------------------------
    # Migrating Certificates
    #--------------------------------------------------
    migrated_certificates = {}
    certificates = pfsense.findall("cert")
    for certificate in certificates:
        crt_name = certificate.find("descr").text
        migrated_certificates[crt_name] = {}
        for element in certificate:
            migrated_certificates[crt_name][element.tag] = element.text if element.tag not in ('crt', 'prv') else ''
        crt_encoded = certificate.find("crt").text
        crt = base64.b64decode(crt_encoded).decode()
        key_encoded = certificate.find("prv").text if authority.find("prv") is not None else None
        key = base64.b64decode(key_encoded).decode() if key_encoded is not None else None
        if not opn.certificate_exists(crt_name):
            opn.import_certificate(crt_name, crt, key)
        else:
            print(f'cert {crt_name} already registered. skipping it.')


    # --------------------------------------------------
    # Migrating Auth Servers 
    #--------------------------------------------------
    existing_auth_servers = opn.get_auth_servers()
    system = pfsense.find("system")
    for authserver in system.findall("authserver"):
        auth_config = {}
        auth_server_name = authserver.find("name").text
        if auth_server_name in existing_auth_servers:
            print(f'Auth server {auth_server_name} already exists. skipping it.')
            continue
        for attr in authserver:
            auth_config[attr.tag] = attr.text
        opn.add_auth_server(auth_config)
    
    
    # --------------------------------------------------
    # Migrating Aliases 
    #--------------------------------------------------
    existing_aliases = [alias['name'] for alias in opn.get_aliases()]
    aliases = pfsense.find("aliases")
    for alias in aliases:
        alias_name = alias[0].text
        alias_type = alias[1].text
        alias_value = alias[2].text
        alias_description = alias[3].text

        # abort if exists
        if alias_name in existing_aliases:
            print(f'alias {alias_name} already exists. skipping it.')
            continue
        
        # convert spaces (separator) into line break
        alias_object = {
            "alias": {
                "name": alias_name, 
                "type":alias_type, 
                "content": alias_value, 
                "enabled":"1", 
                "description":alias_description
            }
        }
        if alias_object["alias"]["content"] is not None:
            alias_object["alias"]["content"] = alias_object["alias"]["content"].replace(" ","\n")
        
        # register it
        opn.add_alias(alias_object)
            

   
    # --------------------------------------------------
    # Migrating OpenVPN Servers 
    #--------------------------------------------------
    openvpn = pfsense.find("openvpn")
    for vpn_server in openvpn.findall("openvpn-server"):
        vpn_config = {}
        for attr in vpn_server:
            vpn_config[attr.tag] = attr.text
        ovpn_servers = opn.get_ovpn_servers()
        if not vpn_config['description'] in ovpn_servers:
            opn.import_openvpn_server(vpn_config)
        else:
            print(f'openvpn server {vpn_config["description"]} already registered. skipping it.')
    


    # --------------------------------------------------
    # Migrating Firewall Rules
    #--------------------------------------------------
    # urgh! a hard one. 
    ifaces = opn.get_assigned_interfaces()
    existing_rules = opn.get_firewall_rules()
    filter = pfsense.find("filter")
    for rule in filter.findall("rule"):
        target_rule = extract_rule_attributes(rule)
        if target_rule is None:
            continue
        
        # get friendly interface name
        pfsense_interfaces = pfsense.find("interfaces")
        pfsense_interface_list = {}
        for interface in pfsense_interfaces:
            descr = interface.find("descr").text
            pfsense_interface_list[interface.tag] = {
                'if': interface.find("if").text,
                'descr': descr
            }
            

        # skip vpn rules by now. we don't support them yet.
        if target_rule["interface"] in ("enc0", "openvpn"):
            print(f"skipping ipsec/openvpn rules as we don't migrated the tunnels  yet")
            continue

        # do not import existing rules
        if target_rule["descr"] in existing_rules[ pfsense_interface_list[target_rule['interface']]['descr'] ]:
            print(f'firewall rule {target_rule["descr"]} already registered. skipping it.')
            continue

        # adjust interface name as in the new firewall
        target_rule["interface"] = ifaces[pfsense_interface_list[target_rule['interface']]['descr']]

        # do not import nat-related rules (skip them)
        if 'associated-rule-id' in target_rule:
            continue

        # base rule attributes
        print(f'working on filter rule: {target_rule["descr"]}')
        new_rule = {"rule":{"enabled":"1","action":target_rule["type"],"quick":"1","interface":target_rule["interface"],"direction":"in","ipprotocol":target_rule.get("ipprotocol", "default_value"),"source_not":"0","destination_not":"0","log":"0","description":target_rule["descr"]}}
        
        # rules with ipv4+ipv6 address family is not supported. forcing as ipv4
        if target_rule.get("ipprotocol", "default_value") == 'inet46':
            print(f'WARN: found firewall rule set as both ipv4+ipv6 thats not compatible with opnsense. the rule will be set only for ipv4! Please, check that!')
            new_rule["rule"]["ipprotocol"] = "inet"
        
        # some fields may be missing from pfsense.
        if 'protocol' in target_rule:
            new_rule["rule"]["protocol"] = target_rule["protocol"]
        if target_rule["source"]["type"] == "any":
            new_rule["rule"]["source_net"] = "any"
        else:
            new_rule["rule"]["source_net"] = target_rule["source"]["value"]
        if 'srcnot' in target_rule["source"]:
            new_rule["rule"]["srcnot"] = "yes"

        #fix source mask
        if target_rule["source"]["value"] is not None and '/' in target_rule["source"]["value"]:
            new_rule["rule"]["source_net"] = target_rule["source"]["value"].split("/")[0]
            new_rule["rule"]["srcmask"] = target_rule["source"]["value"].split("/")[-1]
        
        # destination network/any
        if target_rule["destination"]["type"] == "any":
            new_rule["rule"]["destination_net"] = "any"
        else:
            new_rule["rule"]["destination_net"] = target_rule["destination"]["value"]
        
        # fix destination mask 
        if target_rule["destination"]["value"] is not None and '/' in target_rule["destination"]["value"]:
            new_rule["rule"]["dstmask"] = target_rule["destination"]["value"].split("/")[-1]
            new_rule["rule"]["destination_net"] = target_rule["destination"]["value"].split("/")[0]
        
        # fix dstbeginport
        if 'dstbeginport' in target_rule["destination"]:
            new_rule["rule"]["dstbeginport"] = target_rule["destination"]["dstbeginport"]
        
        # fix gateway
        if 'gateway' in target_rule:
            new_rule["rule"]["gateway"] = target_rule["gateway"]
        
        # floating rule?
        if 'floating' in target_rule:
            new_rule["rule"]["floating"] = 'yes'

        opn.add_filter_rule(new_rule)


    
    # --------------------------------------------------
    # Migrating Firewall NAT (port forwarding)
    #--------------------------------------------------
    ifaces = opn.get_assigned_interfaces()
    existing_nat_rules = opn.get_firewall_nat_rules()
    nat_element = pfsense.find("nat")

    for rule_element in nat_element.findall("rule"):
        target_nat_rule = extract_nat_rule_attributes(rule_element)
        if target_nat_rule is None:
            continue
        else:
            print(f'\nworking on nat rule: {target_nat_rule["descr"]}')

        # put name as tracker if descr is empty
        if target_nat_rule['descr'] is None:
            target_nat_rule['descr'] = rule_element.find("created").find("time").text

        
        # translate interface
        # get friendly interfaces name
        pfsense_interfaces = pfsense.find("interfaces")
        pfsense_interface_list = {}
        for interface in pfsense_interfaces:
            descr = interface.find("descr").text
            pfsense_interface_list[interface.tag] = {
                'if': interface.find("if").text,
                'descr': descr
            }

        # translated interface
        nat_rule_interface = ifaces[pfsense_interface_list[target_nat_rule['interface']]['descr']]

        # do not import existing rules
        if target_nat_rule["descr"] in existing_nat_rules:
            print(f'firewall rule {target_rule["descr"]} already registered. skipping it.')
            continue

        # register the rule
        new_nat_rule = {
            'interface[]': nat_rule_interface,
            'ipprotocol': '',
            'protocol': 'any',
            'src': 'any',
            'srcmask':  '128',
            'srcbeginport': 'any',
            'srcendport': 'any',
            'dst':  'any',
            'dstmask': '32',
            'dstbeginport': '',
            'dstendport': '',
            'target': target_nat_rule["target"],
            'local-port': target_nat_rule["local-port"],
            'descr': target_nat_rule["descr"],
            'natreflection': 'default',
            'filter-rule-association': 'add-associated',
            'Submit': 'Save'
        }
        
        # fix iproto
        if 'ipprotocol' in target_nat_rule:
            new_nat_rule["ipprotocol"] = target_nat_rule["ipprotocol"]
            if target_nat_rule["ipprotocol"] == 'inet46':
                print(f'WARN: found firewall rule set as both ipv4+ipv6 thats not compatible with opnsense. the rule will be set only for ipv4! Please, check that!')
                new_nat_rule["ipprotocol"] = "inet"
        else:
            new_nat_rule["ipprotocol"] = "inet"
        
        # some fields may be ommited from pfsense config
        if 'protocol' in target_nat_rule:
            new_nat_rule["protocol"] = target_nat_rule["protocol"]
            
        if target_nat_rule["source"]["type"] == "any":
            new_nat_rule["src"] = "any"
        else:
            new_nat_rule["src"] = target_nat_rule["source"]["value"]
        
        if 'srcnot' in target_nat_rule["source"]:
            new_nat_rule["srcnot"] = "yes"
        
        # fix for source address with mask
        if target_nat_rule["source"]["value"] is not None and '/' in target_nat_rule["source"]["value"]:
            new_nat_rule["src"] = target_nat_rule["source"]["value"].split("/")[0]
            new_nat_rule["srcmask"] = target_nat_rule["source"]["value"].split("/")[-1]
        
        if target_nat_rule["destination"]["type"] == "any":
            new_nat_rule["dst"] = "any"
        else:
            new_nat_rule["dst"] = target_nat_rule["destination"]["value"]
        
        # fix for dest address with mask 
        if target_nat_rule["destination"]["value"] is not None and '/' in target_nat_rule["destination"]["value"]:
            new_nat_rule["dst"] = target_nat_rule["destination"]["value"].split("/")[0]
            new_nat_rule["dstmask"] = target_nat_rule["destination"]["value"].split("/")[-1]
        
        if 'dstnot' in target_nat_rule["destination"]:
            new_nat_rule["dstnot"] = "yes"
        if 'dstbeginport' in target_nat_rule["destination"]:
            new_nat_rule["dstbeginport"] = target_nat_rule["destination"]["dstbeginport"]
        if 'dstendport' in target_nat_rule["destination"]:
            new_nat_rule["dstendport"] = target_nat_rule["destination"]["dstendport"]
        
        # add the new rule to opnsense
        opn.add_nat_rule(new_nat_rule)


    # click the apply button after all.
    headers = {}
    headers["X-CSRFToken"] = opn.csrftoken
    headers["referer"] = f'{opn.url}/firewall_nat_edit.php'
    headers["content-type"] = "application/x-www-form-urlencoded"
    req = opn.request_post('/firewall_nat.php', data={opn.form_hidden_name: opn.form_hidden_value, 'apply':'Apply changes'}, headers=headers)


    
    # --------------------------------------------------
    # Migrating DHCP
    #--------------------------------------------------
    dhcpd = pfsense.find("dhcpd")
    for dhcpd_interface in dhcpd:
        interface_config = extract_dhcp_attributes(dhcpd_interface)
        interface_config["if"] = dhcpd_interface.tag
    
        req = opn.request_get(f'/services_dhcp.php?if={interface_config["if"]}' )
        
        data = interface_config
        data["submit"] = "Save"
        data[opn.form_hidden_name] = opn.form_hidden_value
        
        headers = {}
        headers["X-CSRFToken"] = opn.csrftoken
        headers["referer"] = f'{opn.url}/services_dhcp.php?if={data["if"]}'
        headers["content-type"] = "application/x-www-form-urlencoded"

        
        # sending form of new dhcp instance config:
        req = opn.request_post(f'/services_dhcp.php?if={data["if"]}', data=data, headers=headers)
        
        if req.status_code == 302:
            print(f'DHCP CONFIG {data["if"]} successfull imported!') 
        else:
            print(f'errro importing dhcp config for interface {data["if"]}.')
            print(req.text)
        
        # import static leases
        static_leases = get_static_dhcp_leases(dhcpd_interface)
        for lease in static_leases:
            lease["if"] = interface_config["if"]
            req = opn.request_get(f'/services_dhcp_edit.php?if={lease["if"]}' )

            data = lease
            data["submit"] = "Save"
            data[opn.form_hidden_name] = opn.form_hidden_value

            headers = {}
            headers["X-CSRFToken"] = opn.csrftoken
            headers["referer"] = f'/services_dhcp_edit.php?if={data["if"]}'
            headers["content-type"] = "application/x-www-form-urlencoded"


            # sending form of new static lease:
            req = opn.request_post(f'/services_dhcp_edit.php?if={data["if"]}', data=data, headers=headers)
            
            if req.status_code == 302:
                print(f'debug status: {req.headers}, {req.text}')
                print(f'DHCP STATIC LEASE {data["descr"]} imported!')
                
            else:
                print(f'error importing static dhcp lease {data["descr"]}.')
                print(req.text)
            
            
            # applying configuration
            headers = {}
            headers["X-CSRFToken"] = opn.csrftoken
            headers["referer"] = f'/services_dhcp_edit.php?if={data["if"]}'
            headers["content-type"] = "application/x-www-form-urlencoded"
            
            data = {
                'apply': 'Apply changes',
                'if': data["if"]
            }
            
            # sending apply action
            req = opn.request_post(f'/services_dhcp.php?if={data["if"]}', data=data, headers=headers)
            
            if req.status_code == 302:
                # successfuly applied configuration
                pass
            else:
                print(f'error applying configuration after static lease import.')




    
    print(f'\n\n===== FINISHED ========')
    
    
