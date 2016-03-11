# -*- coding: utf-8 -*-

"""
cpcloud.azure
~~~~~~~~~~~~~

This module contains the primary objects for querying the Azure cloud API.

Makes a series of Azure REST API requests
to obtain VM instance information required
to build Check Point policy objects.

Tested on Azure REST API version '2015-05-01-preview'
"""
from .exceptions import AzureClientError

import requests

VM_STATUS_RUNNING = "PowerState/running"
API_VER = "2015-05-01-preview"

def normalize_data(vms, vm_statuses, nics, public_ips):
    """
    Normalize the data from a series of Azure cloud API calls into
    a Python dict object containing very specific portions of the original data.

    dict = { '<instance_name>': { 'public_ip': '<public_ip>', 'public_dns_name': '<public_dns_name>',
        'status': '<Up|Down>', 'source': 'Azure' }
    }
    """
    normalized_data = {}
    for vm_id in vms:
        vm_data = vms[vm_id]
        name = vm_data['name']
        nic_id = vm_data['nic_id']
        nic_data = nics[nic_id]
        public_ip_id = nic_data['public_ip_id']
        public_ip_data = public_ips[public_ip_id]
        public_ip = public_ip_data['address']
        public_dns_name = public_ip_data['fqdn']
        status = vm_statuses[vm_id]
        source = "Azure"
        instance_data = { 'public_ip': public_ip, 'public_dns_name': public_dns_name, 'status': status, 'source': source }
        normalized_data[name] = instance_data
    return normalized_data

def get_vm_statuses(sub_id, resource_group, vms, auth_token):
    vm_statuses = {}
    for vm_id in vms:
        vm_data = vms[vm_id]
        name = vm_data['name']
        vm_instance_view_json = get_vm_instance_view(sub_id, resource_group, name, auth_token)
        # iterate over VM statuses
        done = False
        i = 0
        status = "Down"
        while not done:
            try:
                code = vm_instance_view_json["statuses"][i]["code"]
                if code == VM_STATUS_RUNNING:
                    status = "Up"
                    done = True
                i += 1
            except IndexError:
                done = True
        vm_statuses[vm_id] = status
    return vm_statuses

def get_vm_instance_view(sub_id, resource_group, vm_name, auth_token):
    # https://management.azure.com/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/Microsoft.Compute/virtualMachines/{vm-name}/InstanceView?api-version={api-version}
    url = 'https://management.azure.com/subscriptions/'
    url += sub_id
    url += '/resourceGroups/'
    url += resource_group
    url += '/providers/Microsoft.Compute/virtualMachines/'
    url += vm_name
    url += '/InstanceView?api-version='
    url += API_VER
    headers = get_request_headers(auth_token)
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        raise AzureClientError("Failed to get VM instance view for VM name: '%s'" % vm_name, resp.status_code)
    try:
        resp_json = resp.json()
        return resp_json
    except ValueError:
        raise AzureClientError("Failed to decode JSON in get_vm_instance_view()")

def get_all_public_ips_in_resource_group(sub_id, resource_group, auth_token):
    # https://management.azure.com/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/Microsoft.Network/publicIPAddresses?api-version={api-version}
    url = 'https://management.azure.com/subscriptions/'
    url += sub_id
    url += '/resourceGroups/'
    url += resource_group
    url += '/providers/Microsoft.Network/publicIPAddresses?api-version='
    url += API_VER
    headers = get_request_headers(auth_token)
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        raise AzureClientError("Failed to get all public IPs in resource group: '%s'" % resource_group, resp.status_code)
    try:
        resp_json = resp.json()
        return resp_json
    except ValueError:
        raise AzureClientError("Failed to decode JSON in get_all_public_ips_in_resource_group()")

def get_all_nics_in_resource_group(sub_id, resource_group, auth_token):
    # https://management.azure.com/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/Microsoft.Network/networkInterfaces?api-version={api-version}
    url = 'https://management.azure.com/subscriptions/'
    url += sub_id
    url += '/resourceGroups/'
    url += resource_group
    url += '/providers/Microsoft.Network/networkInterfaces?api-version='
    url += API_VER
    headers = get_request_headers(auth_token)
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200: 
        raise AzureClientError("Failed to get all NICs in resource group: '%s'" % resource_group, resp.status_code)
    try:
        resp_json = resp.json()
        return resp_json
    except ValueError:
        raise AzureClientError("Failed to decode JSON in get_all_nics_in_resource_group()")

def get_all_vms_in_resource_group(sub_id, resource_group, auth_token):
    # https://management.azure.com/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/Microsoft.Compute/virtualmachines?api-version={api-version}
    url = 'https://management.azure.com/subscriptions/'
    url += sub_id
    url += '/resourceGroups/'
    url += resource_group
    url += '/providers/Microsoft.Compute/virtualmachines?api-version='
    url += API_VER
    headers = get_request_headers(auth_token)
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        raise AzureClientError("Failed to get all VMs in resource group: '%s'" % resource_group, resp.status_code)
    try:
        resp_json = resp.json()
        return resp_json
    except ValueError:
        raise AzureClientError("Failed to decode JSON in get_all_vms_in_resource_group()")

def parse_get_all_public_ips_resp_json(resp_json):
    public_ips = {}
    done = False
    i = 0
    while not done:
        try:
            #name = resp_json["value"][i]["name"]
            id = resp_json["value"][i]["id"]
            address = ""
            try:
                address = resp_json["value"][i]["properties"]["ipAddress"]
            except KeyError:
                address = "unassigned"
            fqdn = ""
            try:
                fqdn = resp_json["value"][i]["properties"]["dnsSettings"]["fqdn"]
            except KeyError:
                fqdn = "unassigned"
            data = { 'address': address, 'fqdn': fqdn }
            public_ips[id] = data
            i += 1
        except IndexError:
            done = True
    return public_ips

def parse_get_all_nics_resp_json(resp_json):
    nics = {}
    done = False
    i = 0
    while not done:
        try:
            id = resp_json["value"][i]["id"]
            private_ip = resp_json["value"][i]["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"]
            public_ip_id = resp_json["value"][i]["properties"]["ipConfigurations"][0]["properties"]["publicIPAddress"]["id"]
            data = { 'private_ip': private_ip, 'public_ip_id': public_ip_id }
            nics[id] = data
            i += 1
        except IndexError:
            done = True
    return nics

def parse_get_all_vms_resp_json(resp_json):
    vms = {}
    done = False
    i = 0
    while not done:
        try:
            id = resp_json["value"][i]["id"]
            name = resp_json["value"][i]["name"]
            nic_id = resp_json["value"][i]["properties"]["networkProfile"]["networkInterfaces"][0]["id"]
            data = { 'name': name, 'nic_id': nic_id }
            vms[id] = data
            i += 1
        except IndexError:
            done = True
    return vms

def get_request_headers(auth_token):
    headers = {
        'user-agent': 'cp-azure-api-client/0.0.1',
        'content-type': 'application/json; charset=utf8',
        'authorization': 'Bearer ' + auth_token
    }
    return headers

def get_auth_token(endpoint, app_id, app_pw):
    token = get_token_from_client_credentials(endpoint, app_id, app_pw)
    return token

def get_token_from_client_credentials(endpoint, client_id, client_secret):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': 'https://management.core.windows.net/',
    }
    resp = requests.post(endpoint, data=payload)
    if resp.status_code != 200:
        raise AzureClientError('Failed to get auth token', resp.status_code)
    resp_json = resp.json()
    return resp_json['access_token']

class AzureClient:
    def __init__(self, sub_id, token_endpoint, app_id, app_pw, resource_group):
        self.sub_id = sub_id
        self.token_endpoint = token_endpoint
        self.app_id = app_id
        self.app_pw = app_pw
        self.resource_group = resource_group

    def get_instance_data(self):
        auth_token = get_auth_token(self.token_endpoint, self.app_id, self.app_pw)
        all_vms_json = get_all_vms_in_resource_group(self.sub_id, self.resource_group, auth_token)
        vms = parse_get_all_vms_resp_json(all_vms_json)
        vm_statuses = get_vm_statuses(self.sub_id, self.resource_group, vms, auth_token)
        all_nics_json = get_all_nics_in_resource_group(self.sub_id, self.resource_group, auth_token)
        nics = parse_get_all_nics_resp_json(all_nics_json)
        all_public_ips_json = get_all_public_ips_in_resource_group(self.sub_id, self.resource_group, auth_token)
        public_ips = parse_get_all_public_ips_resp_json(all_public_ips_json)
        normalized_data = normalize_data(vms, vm_statuses, nics, public_ips)
        return normalized_data
