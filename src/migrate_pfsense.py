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
# Citra IT - Excelencia em TI
# Script para migrar a configuração do pfSense para o OPNSense
# @Author: luciano@citrait.com.br
# @date: 01/02/2023
# @Version: v0.1
# @Usage: python migrate_opnsense.py

import sys
import json
import urllib3
import requests
import xml.etree.ElementTree as ET
import re
from firewall import Firewall
from functions import migrate_aliases, migrate_rules, extract_rule_attributes, migrate_certificates, migrate_openvpn
from functions import migrate_auth_servers, migrate_static_routes, migrate_dhcp_config, migrate_nat


# user defined variables
firewall_url    = 'https://192.168.1.1'
firewall_user   = 'root'
firewall_passwd = 'P4ssword'



if __name__ == '__main__':
    # disable urllib3 warnings for insecure requests
    # by default opnsense comes with a self-signed certificate, so better disable it.
    urllib3.disable_warnings()
    
    # create a new connection to opnsense
    fw = Firewall(firewall_user, firewall_passwd, firewall_url)
    
    # migrate static routes
    migrate_static_routes(fw, "pfsense.xml")
    
    # migrate certificates
    migrate_certificates(fw, "pfsense.xml")
    
    # migrate auth servers 
    migrate_auth_servers(fw, "pfsense.xml")
    
    # migrate aliases
    migrate_aliases(fw, "pfsense.xml")
    
    # migrate openvpn
    migrate_openvpn(fw, "pfsense.xml")
    
    # migrate firewall rules
    migrate_rules(fw, "pfsense.xml")
    
    # migrate firewall nat
    migrate_nat(fw, "pfsense.xml")
    
    # migrate dhcp configuration
    migrate_dhcp_config(fw, "pfsense.xml")
    
    
    print(f'\n\n===== FINALIZADO ========')
    
    
    sys.exit(0)

    
    
