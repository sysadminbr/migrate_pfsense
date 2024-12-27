#!/usr/bin/env python
import sys
import json
import urllib3
import requests
import xml.etree.ElementTree as ET
import re
from base64 import b64decode
import pdb


# Function: get_pfsense_config
# @Argument(pfsense_config_path) -> str   : pfSense config file on filesystem
# @Returns: XMLElementTree
def get_pfsense_config(pfsense_config_path):
    tree = ET.parse(pfsense_config_path)
    root = tree.getroot()
    return root



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
            if len(rule_attr) > 0:
                # port is a range?
                for dst_attr in rule_attr:
                    if dst_attr.tag == 'not':
                        rule['destination']['dstnot'] = 'yes'
                    elif dst_attr.tag == 'port' and '-' in dst_attr.text:
                        rule['destination']['dstbeginport'] = dst_attr.text.split("-")[0]
                        rule['destination']['dstendport'] = dst_attr.text.split("-")[1]
                    elif dst_attr.tag == 'port':
                        rule['destination']['dstbeginport'] = dst_attr.text
                        rule['destination']['dstendport'] = dst_attr.text
                    elif dst_attr.tag == 'network':
                        rule['destination']['type']  = dst_attr.tag
                        rule['destination']['value'] = dst_attr.text
                    elif dst_attr.tag == 'address':
                        rule['destination']['type']  = dst_attr.tag
                        rule['destination']['value'] = dst_attr.text

        
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
        
        if rule_attr.tag == 'tracker':
            rule['tracker'] = rule_attr.text 
            
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

