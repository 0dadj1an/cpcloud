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
cpcloud.amazon
~~~~~~~~~~~~~~

This module contains the primary objects for querying the Amazon EC2 API.

Makes a proper signed Amazon EC2 API request
using some user specified request parameters.
Parses out specific data from a valid
Amazon EC2 API DescribeInstancesResponse
XML document to obtain VM instance information required
to build Check Point policy objects.

WARNING: Parsing XML can be dangerous. Know the risks.

Derived from the Amazon example API client code

Tested on Amazon EC2 API version '2015-10-01'
"""
from .exceptions import DataNormalizationError, AmazonClientError

import base64, datetime, hashlib, hmac, re 
import xml.etree.ElementTree
import requests

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def get_signature_key(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

def normalize_data(resp_xml):
    """
    Normalize the data from an Amazon EC2 API DescribeInstancesResponse into
    a Python dict object containing very specific portions of the original data.

    dict = { '<instance_name>': { 'public_ip': '<public_ip>', 'public_dns_name': '<public_dns_name>',
        'status': '<Up|Down>', 'source': 'Amazon' }
    }
    """
    normalized_data = {}
    root = None
    ns = None
    try:
        root = xml.etree.ElementTree.fromstring(resp_xml)
    except xml.etree.ElementTree.ParseError:
        raise DataNormalizationError("Unable to parse data, doesn't look like XML")
    m = re.search('{([^\}]+)}', root.tag)
    nsurl = m.group(1)
    ns = {'dir': nsurl} # dir = DescribeInstancesResponse
    rs_items = get_reservation_set_items(root, ns)
    for rs_item in rs_items:
        is_items = get_instances_set_items(rs_item, ns)
        for is_item in is_items:
            name = get_instance_name(is_item, ns)
            status = "Down"
            if is_running(is_item, ns):
                status = "Up"
            source = "Amazon"
            nis_items = get_network_interface_set_items(is_item, ns)
            public_ip = get_public_ip(nis_items[0], ns)
            public_dns_name = get_public_dns_name(nis_items[0], ns)
            instance_data = { 'public_ip': public_ip, 'public_dns_name': public_dns_name, 'status': status, 'source': source }
            normalized_data[name] = instance_data
    return normalized_data

def get_reservation_set(root, ns):
    return root.find('dir:reservationSet', ns)

def get_reservation_set_items(root, ns):
    rs = get_reservation_set(root, ns)
    return rs.findall('dir:item', ns)

def get_instances_set_items(reservation_set_item, ns):
    instances_set = reservation_set_item.find('dir:instancesSet', ns)
    return instances_set.findall('dir:item', ns)

def get_instance_name(instances_set_item, ns):
    instance_name = ""
    tagset = instances_set_item.find('dir:tagSet', ns)
    tagset_items = tagset.findall('dir:item', ns)
    for tagset_item in tagset_items:
        key = tagset_item.find('dir:key', ns)
        value = tagset_item.find('dir:value', ns)
        if key.text == 'Name':
            instance_name = value.text
            break
    return instance_name

# From API docs on EC2 instance state
#
# http://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceState.html
#
#  0 : pending
# 16 : running
# 32 : shutting-down
# 48 : terminated
# 64 : stopping
# 80 : stopped
#
# <instanceState>
#   <code>80</code>
#   <name>stopped</name>
# </instanceState>
def is_running(instances_set_item, ns):
    running = False
    instance_state = instances_set_item.find('dir:instanceState', ns)
    code = instance_state.find('dir:code', ns).text
    name = instance_state.find('dir:name', ns).text
    if code == '16' and name == 'running':
        running = True
    return running

def get_network_interface_set_items(instances_set_item, ns):
    nis = instances_set_item.find('dir:networkInterfaceSet', ns)
    return nis.findall('dir:item', ns)

def get_association(network_interface_set_item, ns):
    return network_interface_set_item.find('dir:association', ns)

def get_public_ip(network_interface_set_item, ns):
    ip = "unassigned"
    assoc = get_association(network_interface_set_item, ns)
    if assoc != None:
        ip = assoc.find('dir:publicIp', ns).text
    return ip

def get_public_dns_name(network_interface_set_item, ns):
    dns_name = "unassigned"
    assoc = get_association(network_interface_set_item, ns)
    if assoc != None:
        dns_name = assoc.find('dir:publicDnsName', ns).text
    return dns_name

def describe_instances(access_key, secret_key, region):
    method = 'POST'
    service = 'ec2'
    host = 'ec2.amazonaws.com'
    endpoint = 'https://ec2.amazonaws.com/'
    content_type = 'application/x-www-form-urlencoded; charset=utf-8'
    request_parameters = 'Action=DescribeInstances&Version=2015-10-01'
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
    canonical_uri = '/'
    canonical_querystring = ''
    canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
    signed_headers = 'content-type;host;x-amz-date'
    payload_hash = hashlib.sha256(request_parameters).hexdigest()
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()
    signing_key = get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
    headers = {'Content-Type':content_type,
               'X-Amz-Date':amz_date,
               'Authorization':authorization_header}
    r = requests.post(endpoint, data=request_parameters, headers=headers)
    if r.status_code != 200:
        raise AmazonClientError('Failed to make "describe instances" AWS EC2 API request', r.status_code)
    resp_xml = r.text
    return resp_xml
 
class AmazonClient:
    def __init__(self, access_key, secret_key, region):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region

    def get_instance_data(self):
        resp_xml = describe_instances(self.access_key, self.secret_key, self.region)
        normalized_data = {}
        try:
            normalized_data = normalize_data(resp_xml)
        except DataNormalizationError:
            raise AmazonClientError('Failed to normalize data in AWS EC2 API "describe instances" response')
        return normalized_data
