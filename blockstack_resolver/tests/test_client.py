#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Username Resolver
    ~~~~~

    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.

    For testing the API from command line
"""

import requests
import json

REMOTE_SERVER = 'https://50.19.215.172'
API_ENDPOINT = '/v1/users/fredwilson'

# -------------------------
def call_api(auth_user, auth_passwd, server='local'):

    url = 'http://localhost:5000' + API_ENDPOINT

    if(server == 'remote'):
        url = REMOTE_SERVER + API_ENDPOINT

    data = {}

    # print url
    # print data

    headers = {'Content-type': 'application/json'}

    # SSL verification is turned off below (need to change that)
    r = requests.get(url, params=data, headers=headers,
                     auth=(auth_user, auth_passwd), verify=False)

    if r.status_code == 401:
        print "Wrong user/passwd"
    else:
        print r.json()
        print '-' * 10

# -------------------------
if __name__ == "__main__":

    import sys
    try:
        auth_user = sys.argv[1]
        auth_passwd = sys.argv[2]
        server = sys.argv[3]
    except:
        print "ERROR: need <auth_user>, <auth_passwd>, <server>"
        exit()

    call_api(auth_user, auth_passwd, server)
