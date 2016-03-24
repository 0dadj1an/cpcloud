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

#                     .__                   .___
#  ____ ______   ____ |  |   ____  __ __  __| _/
#_/ ___\\____ \_/ ___\|  |  /  _ \|  |  \/ __ | 
#\  \___|  |_> >  \___|  |_(  <_> )  |  / /_/ | 
# \___  >   __/ \___  >____/\____/|____/\____ | 
#     \/|__|        \/                       \/ 

"""
cpcloud library
~~~~~~~~~~~~~~~

cpcloud is a convenience library, written in Python, that is useful for
querying instance information from popular cloud providers and using it
in API requests sent to Check Point security gateways.

usage:

AmazonClient:

    >>> from cpcloud.amazon import AmazonClient
    >>> client = AmazonClient(AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION)
    >>> data = client.get_instance_data()
    >>> print(data)

AzureClient:

    >>> from cpcloud.azure import AzureClient
    >>> client = AzureClient(AZURE_SUB_ID,
                             AZURE_TOKEN_ENDPOINT,
                             AZURE_APP_ID,
                             AZURE_APP_PW,
                             AZURE_RESOURCE_GROUP)
    >>> data = client.get_instance_data()
    >>> print(data)

GoogleClient:

    >>> from cpcloud.google import GoogleClient
    >>> client = GoogleClient(GOOGLE_SERVICE_ACCOUNT_CERT_FILE,
                              GOOGLE_SERVICE_ACCOUNT_EMAIL,
                              GOOGLE_PROJECT,
                              GOOGLE_ZONE)
    >>> data = client.get_instance_data()
    >>> print(data)

NuageClient:

    >>> from cpcloud.nuage import NuageClient
    >>> client = NuageClient(NUAGE_HOST,
                             NUAGE_PORT,
                             NUAGE_USERNAME,
                             NUAGE_PASSWORD,
                             NUAGE_ORG)
    >>> data = client.get_instance_data()
    >>> print(data)

IdentityAwarenessClient:

    >>> from cpcloud.checkpoint import IdentityAwarenessClient
    >>> client = IdentityAwarenessClient(CPIDA_GATEWAY_IP, CPIDA_SHARED_SECRET)
    >>> resp_json = client.add_identity('10.1.1.32', 'testmachine', 'testdomain')
    >>> print(resp_json)
    >>> resp_json = client.show_identity('10.1.1.32')
    >>> print(resp_json)

:copyright: (c) 2016 by Dana James Traversie and Check Point Software Technologies, Ltd.
:license: Apache 2.0, see LICENSE for more details.

"""

__title__ = 'cpcloud'
__version__ = '0.0.1'
__build__ = 0x000001
__author__ = 'Dana James Traversie'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2016 Dana James Traversie and Check Point Software Technologies, Ltd.'
