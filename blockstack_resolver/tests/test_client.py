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

REMOTE_SERVER = 'http://resolver.onename.com'
API_ENDPOINT = '/resolver/profile'


# -------------------------
def call_api(username, auth_user, auth_passwd, server='local'):

    url = 'http://localhost:5000' + API_ENDPOINT

    if(server == 'remote'):
        url = REMOTE_SERVER + API_ENDPOINT

    data = {}
    data['username'] = username

    print url
    print data

    headers = {'Content-type': 'application/json'}

    r = requests.get(url, params=data, headers=headers,
                     auth=(auth_user, auth_passwd))

    if r.status_code == 401:
        print "Wrong user/passwd"
    else:
        print r.json()
        print '-' * 10

# -------------------------
if __name__ == "__main__":

    import sys
    try:
        username = sys.argv[1]
        auth_user = sys.argv[2]
        auth_passwd = sys.argv[3]
        server = sys.argv[4]
    except:
        print "ERROR: need <username>, <auth_user>, <auth_passwd>, <server>"
        exit()

    call_api(username, auth_user, auth_passwd, server)
