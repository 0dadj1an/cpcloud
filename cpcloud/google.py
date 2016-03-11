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
cpcloud.google
~~~~~~~~~~~~~~

This module contains the primary objects for querying the Google cloud API.

Makes a series of Google REST API requests
to obtain VM instance information required
to build Check Point policy objects.

Tested on Google REST API version 'v1'
"""

from .exceptions import GoogleClientError

import json

from httplib2 import Http

from oauth2client.client import SignedJwtAssertionCredentials
from apiclient.discovery import build
from googleapiclient.errors import HttpError

UP_STATUS = "RUNNING"

def normalize_data(resp_json):
    """
    Normalize the data from a Google cloud API list instances response into
    a Python dict object containing very specific portions of the original data.

    dict = { '<instance_name>': { 'public_ip': '<public_ip>', 'public_dns_name': '<public_dns_name>',
        'status': '<Up|Down>', 'source': 'Google' }
    }
    """
    normalized_data = {}
    done = False
    i = 0
    while not done:
        try:
            name = resp_json['items'][i]['name']
            status = ""
            status_raw = resp_json['items'][i]['status']
            if status_raw == UP_STATUS:
                status = "Up"
            else:
                status = "Down"
            public_dns_name = "unassigned"
            public_ip = ""
            try:
                public_ip = resp_json['items'][i]['networkInterfaces'][0]['accessConfigs'][0]['natIP']
            except KeyError:
                public_ip = "unassigned"
            instance_data = { 'public_ip': public_ip, 'public_dns_name': public_dns_name, 'status': status, 'source': 'Google' } 
            normalized_data[name] = instance_data
            i += 1
        except IndexError:
            done = True
    return normalized_data

def list_instances(client_cert_file, client_email, project, zone):
    with open(client_cert_file) as f:
        private_key = f.read()
    credentials = SignedJwtAssertionCredentials(client_email, private_key,
        'https://www.googleapis.com/auth/compute.readonly')
    http = Http()
    credentials.authorize(http)
    try:
        compute = build('compute', 'v1', http=http)
        resp_json = compute.instances().list(project=project, zone=zone).execute()
    except HttpError:
        raise GoogleClientError('Failed to make "list instances" Google cloud API request')
    return resp_json

class GoogleClient:
    def __init__(self, client_cert_file, client_email, project, zone):
        self.client_cert_file = client_cert_file
        self.client_email = client_email
        self.project = project
        self.zone = zone

    def get_instance_data(self):
        resp_json = list_instances(self.client_cert_file,
                                   self.client_email,
                                   self.project,
                                   self.zone)
        normalized_data = normalize_data(resp_json)
        return normalized_data
