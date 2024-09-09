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




# Class: Firewall
# @Desc.: Represents a firewall api connection (opnsense)
#
class Firewall:
    def __init__(self, user, password, baseurl):
        self.user = user
        self.password = password
        self.baseurl = baseurl
        self.csrftoken = ''
        self.hidden_name = ''
        self.hidden_value = ''
        self.http_session = requests.Session()
        # login on startup
        self.check_connection()
        

    def check_connection(self):
        print(f'connecting to firewall on {self.baseurl}')
        
        # requesting firewall landing page
        r = self.http_session.get(self.baseurl, verify=False)
        
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token from landing page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")
        
        # submitting login form
        data = {self.hidden_name: self.hidden_value, 'usernamefld': self.user, 'passwordfld': self.password, 'login':'1'}
        r = self.http_session.post(self.baseurl, data=data, verify=False, allow_redirects=False )

        # checking if login was successful
        if r.status_code == 302 and 'Location' in r.headers:
            print(f'[+] firewall login sucessful')
        else:
            print(f'[-] invalid username or password for this firewall')


        
    #
    #
    #    
    def add_alias(self, alias):
        # acessing aliaseses page to grab token
        r = self.http_session.get(f'{self.baseurl}/ui/firewall/alias', verify=False )
        
        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        alias_data = {
            "alias":   {
                "enabled": "1",
                "name": alias["alias"]["name"],
                "type": alias["alias"]["type"],
                "proto": "",
                "categories": "",
                "updatefreq": "",
                "content": alias["alias"]["content"],
                "interface": "",
                "counters": "0",
                "description": alias["alias"]["description"]
            },
            "network_content":""
        }
        
        # setup headers
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/ui/firewall/alias'
        
        # sending form of new alias:
        r = self.http_session.post(f'{self.baseurl}/api/firewall/alias/addItem/', verify=False, json=alias_data, headers=headers)
        if r.status_code == 200:
            print(f'[+] alias criado com sucesso!')
            return True
        else:
            print(f'[-] erro ao cadastrar novo alias.')
            return False




    def list_alias(self):
        url_alias_list  = self.baseurl + 'firewall/alias/get'
        r = requests.get(url_alias_list,  
            verify=False, 
            auth=(self.api_key, self.api_secret))
        if r.status_code == 200:
            print(r.text)
            return True
        else:
            print(f'error adding alias: {r.text}')
            return False


    def del_alias(self, alias):
        pass
    
    
    
    #
    #
    #
    def add_filter_rule(self, rule):
        # acessing form of rules to grab token
        r = self.http_session.get(f'{self.baseurl}/firewall_rules_edit.php?if=lan', verify=False )
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        # filling form data for new rule
        data = {
            self.hidden_name: self.hidden_value, 
            'type': rule["rule"]['action'],
            'quick':'yes',
            'interface': rule["rule"]['interface'],
            'direction':'in',
            'ipprotocol': rule["rule"]['ipprotocol'],
            'protocol': 'any',
            'src': rule["rule"]["source_net"],
            'srcmask':'32',
            'srcbeginport': 'any',
            'srcendport': 'any',
            'dst': rule["rule"]["destination_net"],
            'dstmask':'32',
            'dstbeginport': 'any',
            'dstendport': 'any',
            'descr': rule["rule"]["description"],
            'sched':'',
            'gateway': '',
            'reply-to':'',
            'set-prio':'',
            'set-prio-low':'',
            'prio':'',
            'tos':'',
            'tag':'',
            'tagged':'',
            'max':'',
            'max-src-nodes':'',
            'max-src-conn':'',
            'max-src-states':'',
            'max-src-conn-rate':'',
            'max-src-conn-rates':'',
            'overload':'virusprot',
            'statetimeout':'',
            'adaptivestart':'',
            'adaptiveend':'',
            'os':'',
            'statetype':'keep state',
            'Submit':'Save'
        }
        
        # fix para alguns campos que podem ter sido omitidos nas regras
        if 'floating' in rule["rule"]:
            data["floating"] = "1"
            # for iface in rule["rule"]["interface"].split(",")
                # data["interface[]"]
        if 'gateway' in rule["rule"]:
            data["gateway"] = rule["rule"]["gateway"]
        if 'protocol' in rule["rule"]:
            data["protocol"] = rule["rule"]["protocol"]
        if 'srcnot' in rule["rule"]:
            data["srcnot"] = rule["rule"]["srcnot"]
        if 'srcmask' in rule["rule"]:
            data["srcmask"] = rule["rule"]["srcmask"]
        if 'dstmask' in rule["rule"]:
            data["dstmask"] = rule["rule"]["dstmask"]
        if 'dstbeginport' in rule["rule"]:
            # fix para porta destino como range (one field on pfsense, two separate fields in opnsense).
            if rule["rule"]["dstbeginport"] is not None and '-' in rule["rule"]["dstbeginport"]:
                data["dstbeginport"] = rule["rule"]["dstbeginport"].split("-")[0]
                data["dstendport"] = rule["rule"]["dstbeginport"].split("-")[1]
            else:
                data["dstbeginport"] = rule["rule"]["dstbeginport"]
                data["dstendport"] = rule["rule"]["dstbeginport"]
        

        
        
        #headers = r.headers
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/firewall_rules.php?if=lan'
        headers["content-type"] = "application/x-www-form-urlencoded"
        
        #print(f'DEBUG: {data}')
        
        # sending form of new rule:
        r = self.http_session.post(f'{self.baseurl}/firewall_rules_edit.php?if={data["interface"]}', verify=False, allow_redirects=False, data=data, headers=headers)
        if r.status_code == 302:
            print(f'regra de firewall criada com sucesso!')
            # aplicando as alterações
            r = self.http_session.post(f'{self.baseurl}/firewall_rules.php?if=lan', verify=False, data={self.hidden_name: self.hidden_value, 'act':'apply'})
            if r.status_code == 200:
                pass
                #print(f'configuração aplicada com sucesso!')
            return True
            
        else:
            print(f'erro ao cadastrar nova regra.')
            return False
    
    
    
    
    #
    #
    #
    def add_nat_rule(self, nat_rule):
        # acessing form of nat rules to grab token
        r = self.http_session.get(f'{self.baseurl}/firewall_nat_edit.php', verify=False )
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        # filling form data for new rule
        data = nat_rule
        data[self.hidden_name] = self.hidden_value
        
        
        #headers = r.headers
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/firewall_nat_edit.php'
        headers["content-type"] = "application/x-www-form-urlencoded"
        
        #print(f'DEBUG: {data}')
        
        # sending form of new rule:
        r = self.http_session.post(f'{self.baseurl}/firewall_nat_edit.php', verify=False, allow_redirects=False, data=data, headers=headers)
        if r.status_code == 302:
            print(f'regra de nat criada com sucesso!')
            # aplicando as alterações
            r = self.http_session.post(f'{self.baseurl}/firewall_nat.php', verify=False, data={self.hidden_name: self.hidden_value, 'apply':'Apply changes'})
            if r.status_code == 200:
                pass
                #print(f'configuração aplicada com sucesso!')
            return True
            
        else:
            print(f'erro ao cadastrar nova regra.')
            return False
    
    
    
    
    #
    #
    #
    def import_ca(self, ca):
        # acessing form of new ca (system-> trust->ca)
        r = self.http_session.get(f'{self.baseurl}/system_camanager.php?act=new', verify=False )
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        data = {
            self.hidden_name: self.hidden_value,
            'id': '',
            'act': 'new',
            'descr': ca["descr"],
            'camethod': 'existing',
            'cert': b64decode(ca["crt"]).decode().replace("\\n","\\r\\n"),
            'key': b64decode(ca.get("prv", "")).decode(),  # Using get with a default value
            'serial': '',
            'caref': ca["refid"],
            'save': 'Save',

        }
        
        # fix for serial
        if int(ca["serial"] ) > 0:
            data["serial"] = ca["serial"]
        
        #print(f'DEBUG CA: {data}')
        
        
        #headers = r.headers
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/system_camanager.php?act=new'
        headers["content-type"] = "application/x-www-form-urlencoded"
        
        #print(f'DEBUG: {form_data}')
        
        # sending form of ca import:
        r = self.http_session.post(f'{self.baseurl}/system_camanager.php?act=new', verify=False, allow_redirects=False, data=data, headers=headers)
        #print(f'DEBUG: {r.request.body}')
        #print(f'DEBUG: {r.request.headers}')
        
        if r.status_code == 302:
            print(f'CA {ca["descr"]} importada com sucesso!')
            return True
            
        else:
            #print(f'erro ao importar CA. detalhes: {r.text}')
            print(f'erro ao importar CA.')
            return False
    
    
    
    
    
    #
    #
    #
    def import_certificate(self, cert):
        # acessing form of new ca (system-> trust->ca)
        r = self.http_session.get(f'{self.baseurl}/system_certmanager.php?act=new', verify=False )
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        data = {
            self.hidden_name: self.hidden_value,
            'act': 'new',
            'descr': cert["descr"],
            'certmethod': 'import',
            'cert':  b64decode(cert["crt"]).decode(),
            'key': b64decode(cert["prv"]).decode(),
            'certref': cert["refid"],
            'save': 'Save',

        }

        
        #print(f'DEBUG CERT: {data}')
        
        
        #headers = r.headers
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/system_certmanager.php?act=new'
        headers["content-type"] = "application/x-www-form-urlencoded"
        
        # sending form of ca import:
        r = self.http_session.post(f'{self.baseurl}/system_certmanager.php?act=new', verify=False, allow_redirects=False, data=data, headers=headers)
        #print(f'DEBUG: {r.request.body}')
        #print(f'DEBUG: {r.request.headers}')
        
        if r.status_code == 302:
            print(f'CERTIFICATE {cert["descr"]} importado com sucesso!')
            return True
            
        else:
            #print(f'erro ao importar CA. detalhes: {r.text}')
            print(f'erro ao importar certificado.')
            return False
            
    
    
    
    #
    #
    #
    def import_crl(self, crl, root_config):
        # acessing main page of ca to get id (certref) of target ca
        r = self.http_session.get(f'{self.baseurl}/system_camanager.php', verify=False )
        
        # hold existing ca info
        existing_ca_info = {}
        
        # extract available ca's ids
        matches = re.findall('system_camanager.php\?act=exp&amp;id=(?P<caid>\d+)', r.text)
        for ca_id in matches:
            print(f'looking for registered ca with id {ca_id}')
            # navigate into each ca edit page to get caref
            r = self.http_session.get(f'{self.baseurl}/system_camanager.php?act=edit&id={ca_id}', verify=False )
            #search for name and id
            ca_name_id_match = re.search('<option value="(?P<refid>\w+)">(?P<caname>[^\s]+)</option>', r.text)
            if ca_name_id_match:
                print(f'found ca: {ca_name_id_match.group("refid")} : {ca_name_id_match.group("caname")}')
                # Push info into existing ca list only if a match is found
                existing_ca_info[ca_name_id_match.group("caname")] = ca_name_id_match.group("refid")
            else:
                print("No match found for the CA")
        # get cert name from pfsense config
        target_ca = None
        ca_el = root_config.findall("ca")
        for ca in ca_el:
            ca_attr = {}
            for attr in ca:
                ca_attr[attr.tag] = attr.text
            #print(f'DEBUG CA: {ca_attr}')
            if ca_attr['refid'] == crl['caref']:
                target_ca = ca_attr
        
        if target_ca is None:
            print(f'Error registering crl. could not find CA with refid {crl["caref"]}')
            sys.exit(0)
    
        target_ca_name = target_ca["descr"]
        ca_refid = existing_ca_info.get(target_ca_name, "Unknown CA RefID")
        print(f'DEBUG: crl {crl["descr"]} will be registered for ca {target_ca_name} with refid {ca_refid}')

        data = {
            self.hidden_name: self.hidden_value,
            'act': 'new',
            'descr': crl["descr"],
            'caref': ca_refid,
            'crlmethod': 'internal',
            'crltext':  '',
            'lifetime': '9999',
            'save': 'Save'
        }
        #headers = r.headers
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/system_crlmanager.php'
        headers["content-type"] = "application/x-www-form-urlencoded"
        # Accessing page to register a new CRL using CA ref
        
        r = self.http_session.post(f'{self.baseurl}/system_crlmanager.php?act=new&caref={ca_refid}', verify=False, allow_redirects=False, data=data, headers=headers)



        # Accessing page to register a new CRL using CA ref
        # Replace direct access with .get method
        caref = existing_ca_info.get(target_ca_name, "Unknown CA RefID")
        r = self.http_session.get(f'{self.baseurl}/system_crlmanager.php?act=new&caref={caref}', verify=False )
        
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        

        #print(f'DEBUG CRL FORM DATA: {data}')
        

        
        # sending form of ca import:
        r = self.http_session.post(f'{self.baseurl}/system_crlmanager.php?act=new&caref={ca_refid}', verify=False, allow_redirects=False, data=data, headers=headers)

        
        if r.status_code == 302:
            print(f'CRL {crl["descr"]} importado com sucesso!')
            return True
            
        else:
            #print(f'erro ao importar CA. detalhes: {r.text}')
            print(f'erro ao importar crl {crl["descr"]}.')
            return False
            
        
        ## TODO
        # Register certificates present in CRL.
        # set certificates that make part of crl
        #r = self.http_session.get(f'{self.baseurl}/system_crlmanager.php?act=new&caref={existing_ca_info[target_ca["descr"]]}', verify=False )
            
    
    
    #
    #
    #
    def import_openvpn_server(self, openvpn_config):
        # accessing form of new vpn ( vpn -> openvpn -> servers )
        r = self.http_session.get(f'{self.baseurl}/vpn_openvpn_server.php?act=new', verify=False)
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")   

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            self.csrf_token = match.group("csrftoken")
        
        data = {
            self.hidden_name: self.hidden_value,
            'description': openvpn_config["description"],
            'mode': openvpn_config["mode"],
            'protocol': 'UDP',
            'dev_mode': openvpn_config["dev_mode"],
            'interface': openvpn_config["interface"],
            'local_port': openvpn_config["local_port"],
            'tlsmode': openvpn_config["tls_type"],
            'tls': b64decode(openvpn_config["tls"]).decode(),
            'caref': openvpn_config["caref"],
            'crlref': openvpn_config["crlref"],
            'certref': openvpn_config["certref"],
            'crypto': openvpn_config["data_ciphers"].split(",")[0],
            'digest': openvpn_config["digest"],
            'dns_server1': openvpn_config.get('dns_server1', ''),
            'cert_depth': openvpn_config["cert_depth"],
            'tunnel_network': openvpn_config["tunnel_network"],
            'tunnel_networkv6': '',
            'local_network': openvpn_config["local_network"],
            'local_networkv6': '',
            'remote_network': openvpn_config["remote_network"],
            'remote_networkv6': '',
            'maxclients': openvpn_config["maxclients"],
            'compression': openvpn_config["compression"],
            'dynamic_ip': openvpn_config["dynamic_ip"],
            'netbios_ntype': openvpn_config["netbios_ntype"],
            'netbios_scope': openvpn_config["netbios_scope"],
            'custom_options': openvpn_config["custom_options"],
            'verbosity_level': openvpn_config["verbosity_level"],
            'reneg-sec': '',
            'save': 'Save',
            'act': 'new'
        }
        if 'dns_domain' in openvpn_config:
            data.update({
                'dns_domain_enable': 'yes',
                'dns_domain': openvpn_config.get("dns_domain", ""),
                'dns_server_enable': 'yes',
                'push_register_dns': 'yes'
            })
            for key in ['dns_server1', 'dns_server2', 'dns_server3', 'dns_server4']:
                if key in openvpn_config:
                    data[key] = openvpn_config[key]
        if 'authmode' in openvpn_config:
            data['authmode[]'] = openvpn_config["authmode"]
        if not 'UDP' in openvpn_config["protocol"]:
            data["protocol"] = openvpn_config["protocol"]
        if openvpn_config["username_as_common_name"] == 'enabled':
            data['cso_login_matching'] = 'yes'  

        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/vpn_openvpn_server.php?act=new'
        headers["content-type"] = "application/x-www-form-urlencoded"
        
        r = self.http_session.post(f'{self.baseurl}/vpn_openvpn_server.php?act=new', verify=False, allow_redirects=False, data=data, headers=headers)
        
        if r.status_code == 302:
            print(f'VPN {data["description"]} importada com sucesso!')
            return True
        else:
            print(f'erro ao importar vpn {data["description"]}.')
            return False    

        
        
    
    
    #
    #
    #
    def add_auth_server(self, auth_config):
        # acessing form of new auth server (system->access->servers)
        r = self.http_session.get(f'{self.baseurl}/system_authservers.php?act=new', verify=False )
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        data = {
            self.hidden_name: self.hidden_value,
            'name': auth_config["name"],
            'type': auth_config["type"],
            'ldap_host': auth_config["host"],
            'ldap_port': auth_config["ldap_port"],
            'ldap_urltype': auth_config["ldap_urltype"],
            'ldap_protver': auth_config["ldap_protver"],
            'ldap_binddn': auth_config["ldap_binddn"],
            'ldap_bindpw': auth_config["ldap_bindpw"],
            'ldap_scope': auth_config["ldap_scope"],
            'ldap_basedn': auth_config["ldap_basedn"],
            'ldapauthcontainers': auth_config["ldap_authcn"],
            'ldap_tmpltype': 'msad',
            'ldap_attr_user': auth_config["ldap_attr_user"],
            'save': 'Save'
        }
        
        # fix for data
        if auth_config["ldap_urltype"] == "SSL/TLS Encrypted":
            data["ldap_urltype"] = "SSL - Encrypted"
        if auth_config["ldap_urltype"] == "STARTTLS Encrypted":
            data["ldap_urltype"] = "StartTLS"
        if auth_config["ldap_extended_enabled"] == "yes":
            data["ldap_extended_query"] = auth_config["ldap_extended_query"]
        
        
        #print(f'DEBUG AUTHSERVER: {data}')
        
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/vpn_openvpn_server.php?act=new'
        headers["content-type"] = "application/x-www-form-urlencoded"
        
        # sending form of new auth server:
        r = self.http_session.post(f'{self.baseurl}/system_authservers.php?act=new', verify=False, allow_redirects=False, data=data, headers=headers)
        #print(f'DEBUG: {r.request.body}')
        #print(f'DEBUG: {r.request.headers}')
        
        if r.status_code == 302:
            print(f'AUTH {data["name"]} importado com sucesso!')
            return True
            
        else:
            print(f'erro ao importar authserver {data["name"]}.')
            return False


    
    
    #
    #
    #
    def add_static_route(self, route_config):
        # acessing form of new static route (system->routes->configuration)
        r = self.http_session.get(f'{self.baseurl}/ui/routes', verify=False )
        
        # getting the page token
        # match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        # if match is None:
            # print(f'error parsing token on firewall main page')
            # sys.exit(0)
        # self.hidden_name = match.group("fieldname")
        # self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        data = {
            "route":{
                "disabled":"0",
                "network": route_config["network"],
                "gateway": route_config["gateway"],
                "descr": route_config["descr"]
            }
        }
        
        
        #print(f'DEBUG route: {data}')
        #return
        
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/vpn_openvpn_server.php?act=new'
        headers["x-requested-with"] = "XMLHttpRequest"

        
        # sending form of new route:
        r = self.http_session.post(f'{self.baseurl}/api/routes/routes/addroute/', verify=False, json=data, headers=headers)
        
        if r.status_code == 200:
            print(f'ROUTE {data["route"]["descr"]} importado com sucesso!')
            return True
            
        else:
            print(f'erro ao importar rota {data["route"]["descr"]}.')
            return False



    #
    #
    #
    def set_dhcpd_config(self, dhcpd_config):
        # acessing form of dhcp configuration
        r = self.http_session.get(f'{self.baseurl}/services_dhcp.php?if={dhcpd_config["if"]}', verify=False )
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        data = dhcpd_config
        data["submit"] = "Save"
        data[self.hidden_name] = self.hidden_value
        
        
        print(f'DEBUG dhcpd: {data}')
        #return
        
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/services_dhcp.php?if={data["if"]}'
        headers["content-type"] = "application/x-www-form-urlencoded"

        
        # sending form of new dhcp instance config:
        r = self.http_session.post(f'{self.baseurl}/services_dhcp.php?if={data["if"]}', verify=False, allow_redirects=False, data=data, headers=headers)
        
        if r.status_code == 302:
            #print(f'debug status: {r.headers}, {r.text}')
            print(f'DHCP CONFIG {data["if"]} importado com sucesso!')
            return True
            
        else:
            print(f'erro ao importar config dhcp {data["if"]}.')
            print(r.text)
            return False




    #
    #
    #
    def add_dhcpd_static_lease(self, lease):
        # acessing form of dhcp configuration
        r = self.http_session.get(f'{self.baseurl}/services_dhcp_edit.php?if={lease["if"]}', verify=False )
        
        # getting the page token
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', r.text)
        if match is None:
            print(f'error parsing token on firewall main page')
            sys.exit(0)
        self.hidden_name = match.group("fieldname")
        self.hidden_value = match.group("fieldvalue")

        # check x-csrftoken
        match = re.search('setRequestHeader\("X-CSRFToken", "(?P<csrftoken>[^"]+)"', r.text)
        if match is None:
            print(f'failed to get X-CSRFToken')
            sys.exit(0)
        else:
            #print(f'got X-CSRFToken as {match.group("csrftoken")}')
            self.csrf_token = match.group("csrftoken")
        
        data = lease
        data["submit"] = "Save"
        data[self.hidden_name] = self.hidden_value
        
        
        #print(f'DEBUG dhcpd: {data}')
        #return
        
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/services_dhcp_edit.php?if={data["if"]}'
        headers["content-type"] = "application/x-www-form-urlencoded"


        # sending form of new static lease:
        r = self.http_session.post(f'{self.baseurl}/services_dhcp_edit.php?if={data["if"]}', verify=False, allow_redirects=False, data=data, headers=headers)
        
        if r.status_code == 302:
            #print(f'debug status: {r.headers}, {r.text}')
            print(f'DHCP STATIC LEASE {data["descr"]} importado com sucesso!')
            
        else:
            print(f'erro ao importar dhcp static lease {data["descr"]}.')
            #print(r.text)
            return False
        
        
        # applying configuration
        headers = {}
        headers["X-CSRFToken"] = self.csrf_token
        headers["referer"] = f'{self.baseurl}/services_dhcp_edit.php?if={data["if"]}'
        headers["content-type"] = "application/x-www-form-urlencoded"
        
        data = {
            'apply': 'Apply changes',
            'if': data["if"]
        }
        
        # sending apply action
        r = self.http_session.post(f'{self.baseurl}/services_dhcp.php?if={data["if"]}', verify=False, allow_redirects=False, data=data, headers=headers)
        
        if r.status_code == 302:
            # successfuly applied configuration
            return True
        else:
            print(f'erro ao aplicar configuração do dhcp leases.')
            return False




