# -*- coding: utf-8 -*-

# Copyright 2016 Dana James Traversie and Check Point Software Technologies, Ltd. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
cpcloud.nuage
~~~~~~~~~~~~~

This module contains the primary objects for querying the Nuage Networks cloud API.

Makes a series of Nuage Networks cloud API requests
to obtain VM instance information required
to build Check Point policy objects.

Tested on Nuage Networks cloud API version 'v3_2'
"""

from .exceptions import NuageClientError

import json
import requests

from requests.auth import HTTPBasicAuth

API_ENDPOINTS = { 'login': '/nuage/api/v3_2/me/',
                  'vms': '/nuage/api/v3_2/vms/',
                  'groups': '/nuage/api/v3_2/policygroups/',
                  'subnets': '/nuage/api/v3_2/subnets/',
                  'events': '/nuage/api/v3_2/events/' }

UP_STATUS = "RUNNING"

def get_base_url(host, port):
    base_url = 'https://' + host + ':' + port
    return base_url

def get_headers(org):
    headers = { 'Content-Type': 'application/json', 'X-Nuage-Organization': org }
    return headers

def get_api_key(host, port, username, password, org, verify=True):
    url = get_base_url(host, port)
    url += API_ENDPOINTS['login']
    headers = get_headers(org)
    resp = requests.get(url, auth=HTTPBasicAuth(username, password), headers=headers, verify=verify)
    if resp.status_code != 200:
        raise NuageClientError('Failed to get API key', resp.status_code)
    resp_json = resp.json()
    api_key = resp_json[0]['APIKey']
    return api_key

def get_vms(host, port, username, api_key, org, verify=True):
    url = get_base_url(host, port)
    url += API_ENDPOINTS['vms']
    headers = get_headers(org)
    resp = requests.get(url, auth=HTTPBasicAuth(username, api_key), headers=headers, verify=verify)
    if resp.status_code != 200:
        raise NuageClientError('Failed to get VMs', resp.status_code)
    resp_json = resp.json()
    return resp_json

def normalize_data(vms_resp_json):
    """
    Normalize the data from a Nuage Networks cloud API get VMs response into
    a Python dict object containing very specific portions of the original data.

    dict = { '<instance_name>': { 'public_ip': '<public_ip>', 'public_dns_name': '<public_dns_name>',
        'status': '<Up|Down>', 'source': 'Nuage' }
    }
    """
    normalized_data = {}
    for vm in vms_resp_json:
        i_name = vm['name']
        status = vm['status']
        i_status = 'Down'
        if status == UP_STATUS:
            i_status = 'Up'
        #for vm_ifs in vm['interfaces']:
        #    private_ip = vm_ifs['IPAddress']
        #    public_ip = vm_ifs['associatedFloatingIPAddress']
        private_ip = vm['interfaces'][0]['IPAddress']
        public_ip = vm['interfaces'][0]['associatedFloatingIPAddress']
        i_public_ip = 'unassigned'
        if public_ip != None:
            i_public_ip = public_ip
        i_public_dns_name = 'unassigned'
        i_source = 'Nuage'
        i_data = { 'public_ip': i_public_ip, 'public_dns_name': i_public_dns_name,
                   'status': i_status, 'source': i_source }
        normalized_data[i_name] = i_data
    return normalized_data

class NuageClient:
    def __init__(self, host, port, username, password, org, verify=True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.org = org
        self.verify = verify
        self.api_key = None

    def fetch_and_set_api_key(self, force=False):
        if self.api_key == None or force:
            self.api_key = get_api_key(self.host, self.port, self.username, self.password, self.org, self.verify)

    def set_org(self, org):
        self.org = org
        self.fetch_and_set_api_key(force=True)

    def get_instance_data(self):
        self.fetch_and_set_api_key()
        vms_resp_json = get_vms(self.host, self.port, self.username, self.api_key, self.org, self.verify)
        normalized_data = normalize_data(vms_resp_json)
        return normalized_data
