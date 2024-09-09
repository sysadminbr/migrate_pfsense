#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
Copyright 2023 CITRAIT
//  Permission is hereby granted, free of charge, to any person obtaining a 
//  copy of this software and associated documentation files (the "Software"), 
//  to deal in the Software without restriction, including without limitation 
//  the rights to use, copy, modify, merge, publish, distribute, sublicense, 
//  and/or sell copies of the Software, and to permit persons to whom the 
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in 
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
//  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
//  DEALINGS IN THE SOFTWARE.
"""
import sys
import json
import urllib3
import requests
import xml.etree.ElementTree as ET
import re
from base64 import b64decode
from firewall import Firewall
#import pdb




#
#
#
def get_pfsense_config(pfsense_config_path):
    # opening pfsense xml config
    file = open(pfsense_config_path, "r")
    
    # read from *fp
    tree = ET.parse(file)
    
    # get root element
    root = tree.getroot()
    
    # close file handle
    file.close()
    
    # return root element
    return root


# Function: migrate_aliases
# @Argument(firewall) -> Firewall          : Firewall API connection
# @Argument(pfsense_config_path) -> string : path to pfsense config file in xml format
# @Returns: Null
def migrate_aliases(firewall, pfsense_config_path):
    print(f'\n======== IMPORTING ALIASES')
    
    # get pfsense config as xml
    root = get_pfsense_config(pfsense_config_path)

    # load aliases from pfsense config and register on opnsense
    aliases = root.find("aliases")
    for alias in aliases:
        alias_name = alias[0].text
        alias_type = alias[1].text
        alias_value = alias[2].text
        alias_description = alias[3].text

        alias_object = {"alias": {"name":alias_name, "type":alias_type, "content": alias_value, "enabled":"1", "description":alias_description}}
        # patch alias value to convert pfsense space separator into opnsense \n separator
        if alias_object["alias"]["content"] is not None:
            alias_object["alias"]["content"] = alias_object["alias"]["content"].replace(" ","\n")
        
        # call add_alias on firewall object
        if firewall.add_alias(alias_object):
            print(f'[+] alias {alias_name} registered!')
        else:
            print(f'[-] error adding alias {alias_name}')
            
    print(f'======== IMPORTING ALIASES FINISHED')
            



# Function: migrate_rules
# @Argument(firewall) -> Firewall          : Firewall API connection
# @Argument(pfsense_config_path) -> string : path to pfsense config file in xml format
# @Returns: Null
def migrate_rules(firewall, pfsense_config_path):
    print(f'\n======== IMPORTING PFSENSE RULES')
    
    # get pfsense config as xml
    root = get_pfsense_config(pfsense_config_path)

    # read rules from pfsense config and import into opnsense
    el_filter = root.find("filter")
    for el_rule in el_filter.findall("rule"):
        target_rule = extract_rule_attributes(el_rule)
        if target_rule is None:
            continue
        
        
        
        # debug
        # if not 'descr' in target_rule or target_rule["descr"] != '12- regra float':
            # continue
        
        # do not import nat-related rules (skip them)
        if 'associated-rule-id' in target_rule:
            continue
            print(f'detected nat rule {target_rule["tracker"]}')


        print(f'\nworking on filter rule: {target_rule["descr"]}')
        new_rule = {"rule":{"enabled":"1","action":target_rule["type"],"quick":"1","interface":target_rule["interface"],"direction":"in","ipprotocol":target_rule.get("ipprotocol", "default_value"),"source_not":"0","destination_not":"0","log":"0","description":target_rule["descr"]}}
        
        # fix para regras do pf com ipv4+ipv6 incompatível com opnsense (que é inet ou inet6 mas não inet46)
        if target_rule.get("ipprotocol", "default_value") == 'inet46':
            print(f'WARN: found firewall rule set as both ipv4+ipv6 thats not compatible with opnsense. the rule will be set only for ipv4! Please, check that!')
            new_rule["rule"]["ipprotocol"] = "inet"
        
        # avaliando campos que podem ou não estar inclusos no pfsense
        if 'protocol' in target_rule:
            new_rule["rule"]["protocol"] = target_rule["protocol"]
            
        if target_rule["source"]["type"] == "any":
            new_rule["rule"]["source_net"] = "any"
        else:
            new_rule["rule"]["source_net"] = target_rule["source"]["value"]
        
        if 'srcnot' in target_rule["source"]:
            new_rule["rule"]["srcnot"] = "yes"
        
        #fix for source mask
        if target_rule["source"]["value"] is not None and '/' in target_rule["source"]["value"]:
            new_rule["rule"]["srcmask"] = target_rule["source"]["value"].split("/")[-1]
            new_rule["rule"]["source_net"] = target_rule["source"]["value"].split("/")[0]
        
        if target_rule["destination"]["type"] == "any":
            new_rule["rule"]["destination_net"] = "any"
        else:
            new_rule["rule"]["destination_net"] = target_rule["destination"]["value"]
        
        # fix for dest mask 
        if target_rule["destination"]["value"] is not None and '/' in target_rule["destination"]["value"]:
            new_rule["rule"]["dstmask"] = target_rule["destination"]["value"].split("/")[-1]
            new_rule["rule"]["destination_net"] = target_rule["destination"]["value"].split("/")[0]
        
        if 'dstbeginport' in target_rule["destination"]:
            new_rule["rule"]["dstbeginport"] = target_rule["destination"]["dstbeginport"]
        
        if 'gateway' in target_rule:
            new_rule["rule"]["gateway"] = target_rule["gateway"]
            # print(target_rule["gateway"])
            # continue
        
        if 'floating' in target_rule:
            new_rule["rule"]["floating"] = 'yes'

        # adicionando a regra ao opnsense
        # print(f'== PFSENSE RULE: {target_rule}')
        #print(f'\n== OPNSENSE RULE: {new_rule}')
        if firewall.add_filter_rule(new_rule):
            print(f'[+] rule {new_rule["rule"]["description"]} added with success!')
        else:
            print(f'\2 - continuing with next rule')


            

# Function: extract_rule_attributes
# @Argument(el_rule) -> XMLElementTree   : pfSense config rule as XMLElementTree
# @Returns: Dictionary with firewall rule attributes and values
def extract_rule_attributes(el_rule):
    rule = {}
    if len(el_rule) < 1:
        return
    for rule_attr in el_rule:
        if rule_attr.tag == 'id':
            rule['id'] = rule_attr.text
        if rule_attr.tag == 'tracker':
            rule['tracker'] = rule_attr.text
        if rule_attr.tag == 'type':
            rule['type'] = rule_attr.text
        if rule_attr.tag == 'interface':
            rule['interface'] = rule_attr.text
        if rule_attr.tag == 'ipprotocol':
            rule['ipprotocol'] = rule_attr.text
        if rule_attr.tag == 'tagged':
            rule['tagged'] = rule_attr.text
        if rule_attr.tag == 'max':
            rule['max'] = rule_attr.text
        if rule_attr.tag == 'max-src-nodes':
            rule['max-src-nodes'] = rule_attr.text
        if rule_attr.tag == 'max-src-conn':
            rule['max-src-conn'] = rule_attr.text
        if rule_attr.tag == 'max-src-conn':
            rule['max-src-states'] = rule_attr.text
        if rule_attr.tag == 'statetimeout':
            rule['statetimeout'] = rule_attr.text
        if rule_attr.tag == 'statetype':
            rule['statetype'] = rule_attr.text
        if rule_attr.tag == 'os':
            rule['os'] = rule_attr.text	
        if rule_attr.tag == 'protocol':
            rule['protocol'] = rule_attr.text
        if rule_attr.tag == 'source':
            rule['source'] = {}
            rule['source']['type']  = rule_attr[0].tag
            rule['source']['value'] = rule_attr[0].text
            if len(rule_attr) > 1 and rule_attr[1].tag == 'not':
                rule['source']['srcnot'] = 'yes'
        if rule_attr.tag == 'destination':
            rule['destination'] = {}
            rule['destination']['type']  = rule_attr[0].tag
            rule['destination']['value'] = rule_attr[0].text
            if len(rule_attr) > 1:
                rule['destination']['dstbeginport'] = rule_attr[1].text
        if rule_attr.tag == 'descr':
            rule['descr'] = rule_attr.text
        if rule_attr.tag == 'associated-rule-id':
            rule['associated-rule-id'] = rule_attr.text
        if rule_attr.tag == 'gateway':
            rule['gateway'] = rule_attr.text
        if rule_attr.tag == 'floating':
            rule['floating'] = 'yes'
    
    return rule



# Function: extract_nat_rule_attributes
# @Argument(el_rule) -> XMLElementTree   : pfSense config rule as XMLElementTree
# @Returns: Dictionary with firewall rule attributes and values
def extract_nat_rule_attributes(el_rule):
    rule = {}
    if len(el_rule) < 1:
        # return if this is a empty nat rule
        return
    for rule_attr in el_rule:
        # source
        if rule_attr.tag == 'source':
            rule['source'] = {}
            rule['source']['type']  = rule_attr[0].tag
            rule['source']['value'] = rule_attr[0].text
            if len(rule_attr) > 1 and rule_attr[1].tag == 'not':
                rule['source']['srcnot'] = 'yes'
        
        # destination and port
        if rule_attr.tag == 'destination':
            rule['destination'] = {}
            rule['destination']['type']  = rule_attr[0].tag
            rule['destination']['value'] = rule_attr[0].text
            if len(rule_attr) > 1:
                # port is a range?
                if rule_attr[1].text and '-' in rule_attr[1].text:
                    rule['destination']['dstbeginport'] = rule_attr[1].text.split("-")[0]
                    rule['destination']['dstendport'] = rule_attr[1].text.split("-")[1]
                else:
                    rule['destination']['dstbeginport'] = rule_attr[1].text
                    rule['destination']['dstendport'] = rule_attr[1].text

        if rule_attr.tag == 'ipprotocol':
            rule['ipprotocol'] = rule_attr.text
            
        if rule_attr.tag == 'protocol':
            rule['protocol'] = rule_attr.text

        if rule_attr.tag == 'target':
            rule['target'] = rule_attr.text
        
        if rule_attr.tag == 'local-port':
            rule['local-port'] = rule_attr.text
        
        if rule_attr.tag == 'interface':
            rule['interface'] = rule_attr.text
            
        if rule_attr.tag == 'descr':
            rule['descr'] = rule_attr.text    
            
        if rule_attr.tag == 'associated-rule-id':
            rule['associated-rule-id'] = rule_attr.text   
            

    return rule
    
    

# Function: extract_dhcp_attributes
# @Argument(el_rule) -> XMLElementTree   : pfSense config rule as XMLElementTree
# @Returns: Dictionary with firewall rule attributes and values
def extract_dhcp_attributes(el_dhcp):
    dhcp_instance_config = {}
    for attr in el_dhcp:
        if attr.tag == 'range':
            dhcp_instance_config['range_from'] = attr[0].text if attr[0].tag == 'from' else ''
            dhcp_instance_config['range_to'] = attr[1].text if attr[1].tag == 'to' else ''
        
        if attr.tag == 'enable':
            dhcp_instance_config["enable"] = "yes"
        
        if attr.tag == 'gateway':
            dhcp_instance_config["gateway"] = attr.text
        
        if attr.tag == 'domain':
            dhcp_instance_config["domain"] = attr.text
        
        if attr.tag == 'domainsearchlist':
            dhcp_instance_config["domainsearchlist"] = attr.text
            
        if attr.tag == 'dnsserver':
            # check if we already added a dns entry
            if not 'dns1' in dhcp_instance_config:
                dhcp_instance_config["dns1"] = attr.text
            elif not 'dns2' in dhcp_instance_config:
                dhcp_instance_config["dns2"] = attr.text
            else:
                # skip otherwise. only allow 2 dns addresses for now
                continue
        
               
    return dhcp_instance_config    




# Function: get_static_dhcp_leases
# @Argument(el_rule) -> XMLElementTree   : pfSense config rule as XMLElementTree
# @Returns: Dictionary with firewall rule attributes and values
def get_static_dhcp_leases(el_dhcp):
    dhcp_instance_config = {}
    static_maps = []
    for attr in el_dhcp:
        if attr.tag == 'staticmap':
            attr_list = dict([(x.tag, x.text) for x in attr ])
            #print(f'DEBUG: {attr_list}')
            lease = {
                'mac': attr_list['mac'],
                'cid': attr_list['cid'],
                'ipaddr': attr_list['ipaddr'],
                'hostname': attr_list['hostname'],
                'descr': attr_list['descr'],
                'gateway': '',
                'domain': '',
                'domainsearchlist':  '',
                'defaultleasetime':  '',
                'maxleasetime':  '',
                'Submit': 'Save',
                'if': 'lan'
                
            }

            # fix for dnsservers
            for x in attr:
                if x.tag == 'dnsserver':
                    # check if we already added a dns entry
                    if not 'dns1' in lease:
                        lease["dns1"] = x.text
                    elif not 'dns2' in lease:
                        lease["dns2"] = x.text
                    else:
                        # skip otherwise. only allow 2 dns addresses for now
                        continue
            
            static_maps.append(lease)
            
        
        
        
               
    return static_maps  


# Function: migrate_certificates
# @Argument(firewall) -> Firewall          : Firewall API connection
# @Argument(pfsense_config_path) -> string : path to pfsense config file in xml format
# @Returns: Null
def migrate_certificates(firewall, pfsense_config_path):
    print(f'==== STARTING MIGRATION OF CERTIFICATES')
    
    # get pfsense config as xml
    root = get_pfsense_config(pfsense_config_path)

    # read authorities from pfsense config and import into opnsense
    el_cas = root.findall("ca")
    for el_ca in el_cas:
        ca = {}
    for attr in el_ca:
        ca[attr.tag] = attr.text

    # Check if 'prv' key exists before calling import_ca
    if 'prv' in ca:
        firewall.import_ca(ca)
    else:
        print(f"Skipping CA import due to missing 'prv' key: {ca.get('descr', 'No description')}")
        
    
    # read certificates from pfsense config and import into opnsense
    el_certs = root.findall("cert")
    for el_cert in el_certs:
        cert = {}
        for attr in el_cert:
            cert[attr.tag] = attr.text
        
        firewall.import_certificate(cert)
    
    
    # read certificate revocation list from pfsense config and import into opnsense
    el_crl = root.findall("crl")
    for crl in el_crl:
        crl_data = {}
        crl_data["cert"] = []
        for attr in crl:
            if attr.tag == "cert":
                crl_subcert = {}
                for subcert in attr:
                    if subcert.tag == 'crt':
                        crl_subcert["crt"] = b64decode(subcert.text).decode()
                    elif subcert.tag == 'prv':
                        crl_subcert["prv"] = b64decode(subcert.text).decode()
                    else:
                        crl_subcert[subcert.tag] = subcert.text
                crl_data["cert"].append(crl_subcert)
            else:
                crl_data[attr.tag] = attr.text
        
        #print(f'DEBUG CRL TO BE ADDED: {crl_data}')
        firewall.import_crl(crl_data, root)



# Function: migrate_openvpn
# @Argument(firewall) -> Firewall          : Firewall API connection
# @Argument(pfsense_config_path) -> string : path to pfsense config file in xml format
# @Returns: Null
def migrate_openvpn(firewall, pfsense_config_path):
    print(f'==== STARTING MIGRATION OF OPENVPN')
    
    # get pfsense config as xml
    root = get_pfsense_config(pfsense_config_path)

    # read vpn server list from pfsense and import into opnsense
    openvpn = root.find("openvpn")
    for vpn_server in openvpn.findall("openvpn-server"):
        vpn_config = {}
        for attr in vpn_server:
            vpn_config[attr.tag] = attr.text
        
        #print(f'DEBUG openvpn: {vpn_config}')
        firewall.import_openvpn_server(vpn_config)
        



# Function: migrate_auth_servers
# @Argument(firewall) -> Firewall          : Firewall API connection
# @Argument(pfsense_config_path) -> string : path to pfsense config file in xml format
# @Returns: Null
def migrate_auth_servers(firewall, pfsense_config_path):
    print(f'==== STARTING MIGRATION OF AUTH SERVERS')
    
    # get pfsense config as xml
    root = get_pfsense_config(pfsense_config_path)

    # read auth_server list
    system = root.find("system")
    #auth_servers = system.findall("authserver")
    for authserver in system.findall("authserver"):
        auth_config = {}
        for attr in authserver:
            auth_config[attr.tag] = attr.text
        
        #print(f'DEBUG authserver: {auth_config}')
        firewall.add_auth_server(auth_config)





# Function: migrate_static_routes
# @Argument(firewall) -> Firewall          : Firewall API connection
# @Argument(pfsense_config_path) -> string : path to pfsense config file in xml format
# @Returns: Null
def migrate_static_routes(firewall, pfsense_config_path):
    print(f'==== STARTING MIGRATION OF STATIC ROUTES')
    
    # get pfsense config as xml
    root = get_pfsense_config(pfsense_config_path)

    # read list of static routes
    staticroutes = root.find("staticroutes")
    for route in staticroutes.findall("route"):
        route_config = {}
        for attr in route:
            route_config[attr.tag] = attr.text
        
        #print(f'DEBUG route: {route_config}')
        firewall.add_static_route(route_config)



# Function: migrate_dhcp_config
# @Argument(firewall) -> Firewall          : Firewall API connection
# @Argument(pfsense_config_path) -> string : path to pfsense config file in xml format
# @Returns: Null
def migrate_dhcp_config(firewall, pfsense_config_path):
    print(f'==== STARTING MIGRATION OF DHCP CONFIGURATION')
    
    # get pfsense config as xml
    root = get_pfsense_config(pfsense_config_path)

    # read list of dhcp interfaces
    dhcpd = root.find("dhcpd")
    for dhcpd_interface in dhcpd:
        #for dhcpd_instance in dhcpd_interfaces
        print(f'dhcpd_interface: name:{dhcpd_interface.tag}')
        interface_config = extract_dhcp_attributes(dhcpd_interface)
        interface_config["if"] = dhcpd_interface.tag
        
        #print(f'DEBUG dhcp: {interface_config}')
        firewall.set_dhcpd_config(interface_config)
        
        # import static leases
        static_leases = get_static_dhcp_leases(dhcpd_interface)
        #print(f'DEBUG dhcp static leases: {static_leases}')
        for lease in static_leases:
            #print(f'DEBUG lease: {lease}')
            lease["if"] = interface_config["if"]
            firewall.add_dhcpd_static_lease(lease)










# Function: migrate_nat
# @Argument(firewall) -> Firewall          : Firewall API connection
# @Argument(pfsense_config_path) -> string : path to pfsense config file in xml format
# @Returns: Null
def migrate_nat(firewall, pfsense_config_path):
    print(f'\n======== IMPORTING PFSENSE NAT RULES')
    
    # get pfsense config as xml
    root = get_pfsense_config(pfsense_config_path)

    # read nat rules from pfsense config and import into opnsense
    nat_element = root.find("nat")
    for rule_element in nat_element.findall("rule"):
        target_nat_rule = extract_nat_rule_attributes(rule_element)
        if target_nat_rule is None:
            continue


        print(f'\nworking on nat rule: {target_nat_rule["descr"]}')
        new_nat_rule = {
            'interface[]': target_nat_rule["interface"],
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
            # fix para regras do pf com ipv4+ipv6 incompatível com opnsense (que é inet ou inet6 mas não inet46)
            if target_nat_rule["ipprotocol"] == 'inet46':
                print(f'WARN: found firewall rule set as both ipv4+ipv6 thats not compatible with opnsense. the rule will be set only for ipv4! Please, check that!')
                new_nat_rule["ipprotocol"] = "inet"
        
        # avaliando campos que podem ou não estar inclusos no pfsense
        if 'protocol' in target_nat_rule:
            new_nat_rule["protocol"] = target_nat_rule["protocol"]
            
        if target_nat_rule["source"]["type"] == "any":
            new_nat_rule["src"] = "any"
        else:
            new_nat_rule["src"] = target_nat_rule["source"]["value"]
        
        if 'srcnot' in target_nat_rule["source"]:
            new_nat_rule["srcnot"] = "yes"
        
        #fix for source mask
        if target_nat_rule["source"]["value"] is not None and '/' in target_nat_rule["source"]["value"]:
            new_nat_rule["src"] = target_nat_rule["source"]["value"].split("/")[0]
            new_nat_rule["srcmask"] = target_nat_rule["source"]["value"].split("/")[-1]
        
        if target_nat_rule["destination"]["type"] == "any":
            new_nat_rule["dst"] = "any"
        else:
            new_nat_rule["dst"] = target_nat_rule["destination"]["value"]
        
        # fix for dest mask 
        if target_nat_rule["destination"]["value"] is not None and '/' in target_nat_rule["destination"]["value"]:
            new_nat_rule["dst"] = target_nat_rule["destination"]["value"].split("/")[0]
            new_nat_rule["dstmask"] = target_nat_rule["destination"]["value"].split("/")[-1]
        
        if 'dstbeginport' in target_nat_rule["destination"]:
            new_nat_rule["dstbeginport"] = target_nat_rule["destination"]["dstbeginport"]
        if 'dstendport' in target_nat_rule["destination"]:
            new_nat_rule["dstendport"] = target_nat_rule["destination"]["dstendport"]
        

        # adicionando a regra ao opnsense
        # print(f'== PFSENSE RULE: {target_nat_rule}')
        # print(f'\n== OPNSENSE RULE: {new_nat_rule}')
        if firewall.add_nat_rule(new_nat_rule):
            print(f'[+] rule {new_nat_rule["descr"]} added with success!')
        else:
            print(f'\2 - continuing with next rule')
