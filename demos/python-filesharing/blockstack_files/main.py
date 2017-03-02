#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
This code is public domain.
Used as a demo for Bockstack.
"""

import requests
import urllib
import os
import sys

# need to pip install these
import blockstack_client as bsk
import jsontokens
import keylib

# application domain name (identifies the specific data store)
APPLICATION_NAME = 'files.blockstack.org'

# list of API families
APPLICATION_METHODS = [
    'store_read',
    'store_write',
    'store_admin',
]

# ECDSA private key (different each time)
APPLICATION_KEY = keylib.ECPrivateKey().to_hex()

def bsk_get_url( path, port=6270 ):
    """
    Make a URL to the local blockstack node 
    """
    return 'http://localhost:{}{}'.format(port, path)


def bsk_auth_headers( session ):
    """
    Make authorization headers from a session token
    """
    return {'Authorization': 'bearer {}'.format(session)}


def bsk_get_session( api_password, port=6270 ):
    """
    Connect to the local blockstack node.
    Get back a session.

    Return the session (a JWT string) on success
    Raise on error
    """

    # will call `GET http://localhost:{port}/v1/auth?authRequest={auth JWT}`
    # will get back a session JWT

    # request permission to access the API 
    auth_request = {
        'app_domain': APPLICATION_NAME,
        'methods': APPLICATION_METHODS,
    }

    # authentication: basic {password}
    headers = {
        'Authorization': 'basic {}'.format(api_password)
    }

    # make the authentication token
    signer = jsontokens.TokenSigner()
    auth_token = signer.sign(auth_request, APPLICATION_KEY)

    # ask for a session token
    url = bsk_get_url('/v1/auth?authRequest={}'.format(auth_token), port=port)
    req = requests.get(url, headers=headers )

    if req.status_code == 200:
        # good to go!
        # expect {'session': ses token} JSON response
        payload = req.json()
        session = payload['token']
        return session

    else:
        # whoops!
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


def bsk_make_datastore( session, drivers=None, port=6270 ):
    """
    Make our data store.  The data store will be specific
    to this application's name (APPLICATION_NAME)

    Return the datastore ID on success (even if it already exists)
    Raise on error
    """
    
    # create a datastore with `POST http://localhost:{port}/v1/stores?drivers={drivers}`
    # get back {'status': True, 'app_user_id': datastore ID}
    
    # does this data store already exist?
    auth_headers = bsk_auth_headers(session)
    url = bsk_get_url('/v1/stores/{}'.format(APPLICATION_NAME), port=port)
    req = requests.get(url, headers=auth_headers)

    if req.status_code == 200:
        # the data store already exists.  Give back it's ID
        datastore_info = req.json()
        datastore_id = datastore_info['datastore_id']
        return datastore_id

    elif req.status_code != 404:
        # some other error
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))

    # doesn't exist yet.  Go create it.
    url = bsk_get_url('/v1/stores', port=port)
    
    if drivers is not None:
        # include requested drivers
        url += '?drivers={}'.format( urllib.quote(','.join(drivers)) )

    req = requests.post(url, headers=auth_headers)

    if req.status_code == 200:
        # succeeded!
        # get back the ID 
        datastore_res = req.json()
        datastore_id = datastore_res['datastore_id']
        return datastore_id

    else:
        # something broke! 
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))
   

def bsk_delete_datastore( session, port=6270 ):
    """
    Delete our data store.

    Return True on success
    Raise on error
    """

    # delete datastore with `DELETE http://localhost:{port}/v1/stores`

    auth_headers = bsk_auth_headers(session)
    url = bsk_get_url('/v1/stores', port=port)
    req = requests.delete(url, headers=auth_headers)

    if req.status_code == 200:
        # success!
        return True

    else:
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


def bsk_put_file( session, datastore_id, local_path, bsk_path, port=6270 ):
    """
    Put the file data pointed to by {local_path} into
    {bsk_path}

    Return True on success
    Raise on error
    """

    # put the file with `POST http://localhost:{port}/v1/stores/{store ID}/files?path={bsk_path}`
    # get back {'status': True}

    # get data from disk 
    with open(local_path, 'r') as f:
        data = f.read()

    # issue the request to store
    auth_headers = bsk_auth_headers(session)
    url = bsk_get_url('/v1/stores/{}/files?path={}'.format(datastore_id, urllib.quote(bsk_path)), port=port)
    req = requests.post(url, headers=auth_headers, data=data)

    if req.status_code == 200:
        # success!
        return True

    else:
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


def bsk_get_file( session, datastore_id, bsk_path, port=6270, file=sys.stdout ):
    """
    Get the file data pointed to by {bsk_path} from the data store.
    Write it to stdout by default (override with file=)

    Return True on success
    Raise on error
    """

    # get the file with `GET http://localhost:{port}/v1/stores/{store ID}/files?path={bsk_path}`
    # get back raw data (application/octet-stream)
    
    # issue the request to fetch 
    auth_headers = bsk_auth_headers(session)
    url = bsk_get_url('/v1/stores/{}/files?path={}'.format(datastore_id, urllib.quote(bsk_path)), port=port)
    req = requests.get(url, headers=auth_headers)

    if req.status_code == 200:
        # success!
        print >> file, req.content
        return True

    else:
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


def bsk_delete_file( session, datastore_id, bsk_path, port=6270 ):
    """
    Delete the file data pointed to by {bsk_path} from the data store.
    
    Return True on success
    Raise on error
    """
    
    # delete with `DELETE http://localhost:{port}/v1/stores/{store ID}/files?path={bsk_path)`
    # get back {'status': True}

    # issue the request 
    auth_headers = bsk_auth_headers(session)
    url = bsk_get_url('/v1/stores/{}/files?path={}'.format(datastore_id, urllib.quote(bsk_path)), port=port)
    req = requests.delete(url, headers=auth_headers)

    if req.status_code == 200:
        # success!
        return True

    else:
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


def bsk_mkdir( session, datastore_id, bsk_path, port=6270 ):
    """
    Make a directory at {bsk_path} in the given data store

    Return True on success
    Raise on error
    """

    # make the directory with `POST http://localhost:{port}/v1/stores/{store ID}/directories?path={bsk_path}`
    # get back {'status': True} (http 200)

    # issue the request to fetch 
    auth_headers = bsk_auth_headers(session)
    url = bsk_get_url('/v1/stores/{}/directories?path={}'.format(datastore_id, urllib.quote(bsk_path)), port=port)
    req = requests.post(url, headers=auth_headers)

    if req.status_code == 200:
        # success!
        return True

    else:
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


def bsk_listdir( session, datastore_id, bsk_path, port=6270, file=sys.stdout ):
    """
    List a directory at {bsk_path} in the given data store.
    Write the listing to stdout.

    Return True on success
    Raise on error
    """

    # list the directory with `GET http://localhost:{port}/v1/stores/{store ID}/directories?path={bsk_path}`
    # get back the structured inode of the directory.
    # iterate through the inode's children and print their names and types (i.e. append '/' to directories)

    # issue the request to fetch
    auth_headers = bsk_auth_headers(session)
    url = bsk_get_url('/v1/stores/{}/directories?path={}'.format(datastore_id, urllib.quote(bsk_path)), port=port)
    req = requests.get(url, headers=auth_headers)

    if req.status_code == 200:
        # success!
        dir_listing = req.json()
        
        # extract names and types
        names = []
        for name in dir_listing.keys():
            dirent = dir_listing[name]
            if dirent['type'] == 2:    # this is a file
                name += '/'

            names.append(name)

        names.sort()
        print >> file, '\n'.join(names)
        return True

    else:
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


def bsk_rmdir( session, datastore_id, bsk_path, port=6270 ):
    """
    Remove a directory at {bsk_path} in the given data store.
    
    Return True on success
    Raise on error
    """

    # delete the directory with `DELETE http://localhost:{port}/v1/stores/{store ID}/directories?path={bsk_path}`
    
    # issue the request 
    auth_headers = bsk_auth_headers(session)
    url = bsk_get_url('/v1/stores/{}/directories?path={}'.format(datastore_id, urllib.quote(bsk_path)), port=port)
    req = requests.delete(url, headers=auth_headers)

    if req.status_code == 200:
        # success!
        return True

    else:
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


if __name__ == '__main__':
    # unit tests!
    import StringIO

    api_password = sys.argv[1]
    ses = bsk_get_session(api_password)
    assert ses, "Failed to authentcate"

    datastore_id = bsk_make_datastore(ses, ['disk'])
    assert datastore_id, "Failed to make datastore"

    # load something 
    with open("/tmp/.footest", 'w') as f:
        f.write("hello world\x00\x01\x02\x03\x04")

    res = bsk_put_file(ses, datastore_id, "/tmp/.footest", "/foo")
    assert res, "Failed to put file"

    # get it back 
    sb = StringIO.StringIO()
    res = bsk_get_file(ses, datastore_id, "/foo", file=sb)
    assert res, "Failed to get file"
    assert sb.getvalue() == "hello world\x00\x01\x02\x03\x04\n", "Got wrong data ({})".format(sb.getvalue())

    # make a directory 
    res = bsk_mkdir(ses, datastore_id, "/bar")
    assert res, "Failed to mkdir"

    # list directory 
    sb = StringIO.StringIO()
    res = bsk_listdir(ses, datastore_id, "/", file=sb)
    assert res, "Failed to listdir"
    assert sb.getvalue() == "bar/\nfoo\n", "Got wrong dir ({})".format(sb.getvalue())

    # delete file 
    res = bsk_delete_file(ses, datastore_id, '/foo')
    assert res

    # delete directory 
    res = bsk_rmdir(ses, datastore_id, '/bar')
    assert res

    # delete datastore
    res = bsk_delete_datastore(ses)
    assert res

