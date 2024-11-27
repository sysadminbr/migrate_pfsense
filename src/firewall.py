#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import sys
import json
import urllib3
import requests
import xml.etree.ElementTree as ET
import re
from base64 import b64decode
from bs4 import BeautifulSoup
import pdb


class WebClient:
    def __init__(self, url='', user='', password=''):
        self.url = url
        self.user = user
        self.password = password
        self.csrftoken = ''
        self.http_session = requests.Session()
        self.check_credentials()
    

    

class OPNsense(WebClient):
    def __init__(self, url='', user='', password=''):
        super().__init__(url, user, password)
        self.form_hidden_name = ''
        self.form_hidden_value = ''


    def update_csrftoken(self, req):
        match = re.search(r'"X-CSRFToken", "(?P<csrftoken>[^"]+)"', req.text)
        if match is not None:
            self.csrftoken = match.group("csrftoken")

    def import_hidden_values(self, req):
        match = re.search('input type="hidden" name="(?P<fieldname>[^"]+)" value="(?P<fieldvalue>[^"]+)', req.text)
        if match is not None:
            self.form_hidden_value = match.group("fieldvalue")
            self.form_hidden_name = match.group("fieldname")

    def request_get(self, endpoint):
        req = self.http_session.get(str(self.url) + str(endpoint), verify=False)
        self.update_csrftoken(req)
        return req
    
    def request_post(self, endpoint='/', data='', headers={}):
        resp = self.http_session.post(
            self.url + endpoint, 
            headers=headers,
            data=data, 
            verify=False, 
            allow_redirects=False
        )
        return resp

    def check_credentials(self):
        # request landing page
        r = self.request_get('/')
        self.import_hidden_values(r)

        # submitting login form
        login_data = {self.form_hidden_name: self.form_hidden_value, 'usernamefld': self.user, 'passwordfld': self.password, 'login':'1'}
        r = self.request_post('', data=login_data )
        

        # checking if login was successful
        if r.status_code == 302 and 'Location' in r.headers:
            print(f'[+] firewall login sucessful')
            next_url = r.headers.get("Location")
            print(f'going next url: {next_url}')
            req = self.http_session.get(self.url + r.headers.get("Location"), verify=False )
            self.update_csrftoken(req)
        else:
            print(f'[-] invalid username or password for this firewall')

    def list_gateways(self):
        pass

    def add_route(self, network='', gateway='"Null4"', description='', disabled='0'):
        #https://192.168.100.156/api/routes/routes/addroute/
        #{"route":{"disabled":"0","network":"199.199.199.199/32","gateway":"01VIVO500MB_DHCP","descr":"one-nine-nine"}}
        route = {
            "route":{
                "disabled": disabled,
                "network": network,
                "gateway": gateway,
                "descr": description
            }
        }
        req = self.request_post(
            endpoint='/api/routes/routes/addroute/',
            data=json.dumps(route),
            headers={'x-csrftoken': self.csrftoken, 'content-type': 'application/json'}
        )
        resp = req.json()
        if 'result' in resp:
            if resp['result'] == 'saved':
                print(f'[+] route added successfuly')
            else:
                print(f'[-] error adding route')
                print(resp)
        else:
            print(f'error on request {req.request}')

    def get_routes(self):
        # https://192.168.100.156/api/routes/routes/searchroute/
        # {"current":1,"rowCount":7,"sort":{},"searchPhrase":""}
        search_data = {"current":1,"rowCount":100,"sort":{},"searchPhrase":""}
        headers = {'x-csrftoken': self.csrftoken,  'content-type': 'application/json'}
        resp = self.request_post(
            endpoint='/api/routes/routes/searchroute/', 
            data=json.dumps(search_data), 
            headers=headers
        )
        return resp.json()['rows']

    def route_exists(self, network):
        my_routes = self.get_routes()
        for route in my_routes:
            if route['network'] == network:
                return True
        return False
        

    def import_ca_certificate(self, name='', crt_payload='', prv_payload=''):
        # https://192.168.100.156/api/trust/ca/add/
        # {"ca":{"action":"existing","descr":"CA-IMPORTADA","key_type":"2048","digest":"sha256","caref":"","lifetime":"825","country":"NL","state":"","city":"","organization":"","organizationalunit":"","email":"","commonname":"","ocsp_uri":"","crt_payload":"-----BEGIN CERTIFICATE-----\n","prv_payload":"","serial":""}}
        ca_certificate = {
            "ca":{
                "action": "existing",
                "descr": name,
                "crt_payload": crt_payload,
                "prv_payload": prv_payload
            }
        }
        req = self.request_post(
            endpoint='/api/trust/ca/add/',
            data=json.dumps(ca_certificate),
            headers={'x-csrftoken': self.csrftoken, 'content-type': 'application/json'}
        )
        resp = req.json()
        if 'result' in resp:
            if resp['result'] == 'saved':
                print(f'[+] ca authority imported successfuly')
            else:
                print(f'[-] error importing ca authority')
        else:
            print(f'error on request {req.request}')

    def get_ca_certificates(self):
        # https://192.168.100.156/api/trust/ca/search/
        # {"current":1,"rowCount":7,"sort":{},"searchPhrase":""}
        search_data = {"current":1,"rowCount":100,"sort":{},"searchPhrase":""}
        headers = {'x-csrftoken': self.csrftoken,  'content-type': 'application/json'}
        resp = self.request_post(
            endpoint='/api/trust/ca/search/', 
            data=json.dumps(search_data), 
            headers=headers
        )
        return resp.json()['rows']


    def ca_certificate_exists(self, descr):
        ca_list = [ x['descr'] for x in self.get_ca_certificates() ]
        return True if descr in ca_list else False
    

    def import_certificate(self, name='', crt_payload='', prv_payload=''):
        # https://192.168.100.156/api/trust/cert/add/
        # {"cert":{"action":"import","descr":"CERTIFICADO","crt_payload":"","prv_payload":""}}
        certificate = {
            "cert":{
                "action": "import",
                "descr": name,
                "crt_payload": crt_payload,
                "prv_payload": prv_payload
            }
        }
        req = self.request_post(
            endpoint='/api/trust/cert/add/',
            data=json.dumps(certificate),
            headers={'x-csrftoken': self.csrftoken, 'content-type': 'application/json'}
        )
        resp = req.json()
        if 'result' in resp:
            if resp['result'] == 'saved':
                print(f'[+] certificate imported successfuly')
            else:
                print(f'[-] error importing certificate')
                print(resp.text)
        else:
            print(f'error on request {req.request}')


    def get_certificates(self):
        # https://192.168.100.156/api/trust/cert/search/
        # {"current":1,"rowCount":7,"sort":{},"searchPhrase":""}
        search_data = {"current":1,"rowCount":100,"sort":{},"searchPhrase":""}
        headers = {'x-csrftoken': self.csrftoken,  'content-type': 'application/json'}
        resp = self.request_post(
            endpoint='/api/trust/cert/search/', 
            data=json.dumps(search_data), 
            headers=headers
        )
        return resp.json()['rows']
            
    def certificate_exists(self, descr):
        crt_list = [ x['descr'] for x in self.get_certificates() ]
        return True if descr in crt_list else False
    
    def add_auth_server(self, auth_config):
        req = self.request_get(endpoint='/system_authservers.php?act=new' )        
        data = {
            self.form_hidden_name: self.form_hidden_value,
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
        
        # fix for when using ssl/tls ldap
        if auth_config["ldap_urltype"] == "SSL/TLS Encrypted":
            data["ldap_urltype"] = "SSL - Encrypted"
        elif auth_config["ldap_urltype"] == "STARTTLS Encrypted":
            data["ldap_urltype"] = "StartTLS"

        # fix for using group limited auth
        if auth_config["ldap_extended_enabled"] == "yes":
            data["ldap_extended_query"] = auth_config["ldap_extended_query"]
        elif auth_config["ldap_pam_groupdn"] is not None:
            data["ldap_extended_query"] = "memberof=%s" % (auth_config["ldap_pam_groupdn"])
        
        headers = {
            'X-CSRFToken': self.csrftoken,
            'content-type': 'application/x-www-form-urlencoded'
        }
        req = self.request_post(endpoint='/system_authservers.php?act=new', data=data, headers=headers)
        if req.status_code == 302:
            print(f'[+] AUTH {data["name"]} successfuly imported!')
            return True
        else:
            print(f'[-] error importing authserver {data["name"]}.')
            print(req.text)
            return False

    def get_auth_servers(self):
        req = self.request_get(endpoint='/system_authservers.php')
        bs = BeautifulSoup(req.text, 'html.parser')
        auth_servers = []
        for row in bs.find("table").find("tbody").find_all("tr"):
            for auth_server_name in row.find("td"):
                auth_servers.append(auth_server_name.text)
        return auth_servers

    def add_alias(self, alias):
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
            "network_content":"",
            "authgroup_content": ""
        }
        headers = {
            'X-CSRFToken': self.csrftoken,
            'referer': '%s/ui/firewall/alias' % self.url,
            'content-type': 'application/json'
        }
        req = self.request_post(endpoint='/api/firewall/alias/addItem/', data=json.dumps(alias_data), headers=headers)
        if req.status_code == 200:
            print(f'[+] alias {alias["alias"]["name"]} successfuly created!')
            return True
        else:
            print(f'[-] error registering alias {alias["alias"]["name"]}.')
            return False

    def get_aliases(self):
        # https://192.168.100.156/api/firewall/alias/searchItem
        # {"current":1,"rowCount":7,"sort":{},"searchPhrase":""}
        search_data = {"current":1,"rowCount":999,"sort":{},"searchPhrase":""}
        headers = {'x-csrftoken': self.csrftoken,  'content-type': 'application/json'}
        resp = self.request_post(
            endpoint='/api/firewall/alias/searchItem', 
            data=json.dumps(search_data), 
            headers=headers
        )
        return resp.json()['rows']

    def import_openvpn_server(self, openvpn_config):
        # format data
        data = {
            self.form_hidden_name: self.form_hidden_value,
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
        
        # convert tunnel_network and local_network from alias to cidr
        aliases = self.get_aliases()
        for alias in aliases:
            if alias['name'] == data['tunnel_network']:
                data['tunnel_network'] = alias['content']
            
        clean_local_network = []
        for local_network in data['local_network'].split(","):
            bAliasFound = False
            for alias in aliases:
                if local_network.strip() == alias['name'].strip():
                    clean_local_network.append( alias['content'].replace("\n",",") )
                    bAliasFound = True
                    break
            if not bAliasFound:
                clean_local_network.append( local_network )
        data['local_network'] = ','.join(clean_local_network)
        

        # fix for dns domain registration and servers
        if 'dns_domain' in openvpn_config and openvpn_config['dns_domain'] is not None:
            data.update({
                'dns_domain_enable': 'yes',
                'dns_domain': openvpn_config.get("dns_domain", ""),
                'dns_server_enable': 'yes',
                'push_register_dns': 'yes'
            })
            for key in ['dns_server1', 'dns_server2', 'dns_server3', 'dns_server4']:
                if key in openvpn_config:
                    data[key] = openvpn_config[key]

        # auth
        if 'authmode' in openvpn_config:
            data['authmode[]'] = openvpn_config["authmode"]

        # protocol
        if 'UDP' != openvpn_config["protocol"]:
            data["protocol"] = openvpn_config["protocol"]

        # use common name instead of certificate cn
        if openvpn_config["username_as_common_name"] == 'enabled':
            data['cso_login_matching'] = 'yes'  

        headers = {
            'X-CSRFToken': self.csrftoken,
            'Referer': '%s/vpn_openvpn_server.php?act=new' % self.url,
            'content-type': 'application/x-www-form-urlencoded'
        }
        
        # submit it
        req = self.request_post(endpoint='/vpn_openvpn_server.php?act=new', data=data, headers=headers)
        
        if req.status_code == 302:
            print(f'[+] OpenVPN server {data["description"]} successfuly imported!')
        else:
            print(f'error importing openvpn server {data["description"]}.')

    
    def get_ovpn_servers(self):
        req = self.request_get(endpoint='/vpn_openvpn_server.php')
        bs = BeautifulSoup(req.text, 'html.parser')
        ovpn_servers = []
        for row in bs.find("table").find("tbody").find_all("tr"):
            ovpn_server = row.find_all("td")[3].text.strip()
            ovpn_servers.append(ovpn_server)
        return ovpn_servers


    def get_firewall_rules(self, interface=''):
        all_rules = []
        assigned_interfaces = self.get_assigned_interfaces()
        if interface != '':
            interfaces_to_search = interface
        else:
            interfaces_to_search = list(assigned_interfaces.keys())
        
        interface_rules = {}
        for interface in interfaces_to_search:
            interface_rules[interface] = []
            if_device_name = assigned_interfaces[interface]
            req = self.request_get(endpoint=f'/firewall_rules.php?if={if_device_name}')
            bs = BeautifulSoup(req.text, 'html.parser')
            for rule_row in bs.find_all("td", {'class': 'rule-description'}):
                rule_name = rule_row.text.split("\n")[1].strip()
                interface_rules[interface].append(rule_name)
        return interface_rules
    

    def get_firewall_nat_rules(self):
        rdr = []
        req = self.request_get(endpoint=f'/firewall_nat.php')
        bs = BeautifulSoup(req.text, 'html.parser')
        for rule_row in bs.find_all("td", {'class': 'rule-description'}):
            rule_name = rule_row.text.split("\n")[1].strip()
            rdr.append(rule_name)
        return rdr



    def get_assigned_interfaces(self):
        req = self.request_get(endpoint='/interfaces_assign.php')
        bs = BeautifulSoup(req.text, 'html.parser')
        interfaces = {}
        for row in bs.find("table").find("tbody").find_all("tr"):
            ifname = row.find_all("td")[0].text.strip().replace("[","").replace("]","")
            ifident = row.find_all("td")[1].text.strip()
            interfaces[ifname] = ifident
        return interfaces


    def add_filter_rule(self, rule):
        data = {
            self.form_hidden_name: self.form_hidden_value, 
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
        
        # fix for some fields that can be ommited by pfsense
        if 'floating' in rule["rule"]:
            data["floating"] = "1"
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
            # fix for destination port as range (one field on pfsense, two separate fields in opnsense).
            if rule["rule"]["dstbeginport"] is not None and '-' in rule["rule"]["dstbeginport"]:
                data["dstbeginport"] = rule["rule"]["dstbeginport"].split("-")[0]
                data["dstendport"] = rule["rule"]["dstbeginport"].split("-")[1]
            else:
                data["dstbeginport"] = rule["rule"]["dstbeginport"]
                data["dstendport"] = rule["rule"]["dstbeginport"]
        

        
        
        #headers = r.headers
        headers = {
            'X-CSRFToken': self.csrftoken,
            'Referer': '{self.url}/firewall_rules.php?if=%s' % (data["interface"]),
            'content-type': 'application/x-www-form-urlencoded'
        }
        
        # sending form of new rule:
        r = self.request_post(endpoint='/firewall_rules_edit.php?if={data["interface"]}', data=data, headers=headers)
        if r.status_code == 302:
            print(f'[+] firewall rule {data["descr"]} created!')
            # aplicando as alterações
            r = self.request_post(endpoint='/firewall_rules.php?if={data["interface"]}', data={self.form_hidden_name: self.form_hidden_value, 'act':'apply'})
            if r.status_code == 200:
                print(f'rule {data["descr"]} applyed successfuly!')
            return True
            
        else:
            print(f'error registering rule {data["descr"]}')
            return False


    def add_nat_rule(self, nat_rule):
        # filling form data for new rule
        data = nat_rule
        data[self.form_hidden_name] = self.form_hidden_value
        
        
        #headers = r.headers
        headers = {}
        headers["X-CSRFToken"] = self.csrftoken
        headers["referer"] = f'{self.url}/firewall_nat_edit.php'
        headers["content-type"] = "application/x-www-form-urlencoded"
        
        # sending form of new rule:
        # !! TODO - just create the rdr, let apply later.
        r = self.request_post('/firewall_nat_edit.php', data=data, headers=headers)
        if r.status_code == 302:
            print(f'[+] rdr rule {data["descr"]} added with success!')
            return True            
        else:
            print(f'[-] Error registering rdr {data["descr"]}')
            return False
    



