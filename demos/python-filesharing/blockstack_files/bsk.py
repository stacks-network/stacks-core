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
import blockstack_client.data as bsk_data
import blockstack_client.rpc as bsk_rpc

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
APPLICATION_KEY = '471309724900922297f1e60d4b3649d86c2affa05bffd64396e3b445420362a8'

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
        'app_public_key': bsk.get_pubkey_hex(APPLICATION_KEY)
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
        # expect {'token': ses token} JSON response
        payload = req.json()
        session = payload['token']
        return session

    else:
        # whoops!
        raise Exception("HTTP status {} from Blockstack on {}".format(req.status_code, url))


def bsk_make_datastore( session, drivers ):
    """
    Make our data store.  The data store will be specific
    to this application's name (APPLICATION_NAME).

    This method is idempotent.  If the data store already exists,
    then no action will be taken (except to query the ID)

    Return the datastore ID on success (even if it already exists).
    Raise on error
    """
    
    # create a datastore with `POST http://localhost:{port}/v1/stores?drivers={drivers}`
    # get back {'status': True, 'datastore_id': datastore ID}

    global APPLICATION_KEY
    datastore_pk = APPLICATION_KEY
    datastore_pubkey = bsk.get_pubkey_hex(datastore_pk)

    datastore_id = bsk_data.datastore_get_id(datastore_pubkey)
   
    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    # get back datastore?
    ds_res = rpc.backend_datastore_get( datastore_id )
    if 'error' not in ds_res:
        return {'status': True, 'datastore': ds_info, 'datastore_id': datastore_id}

    # make one!
    ds_info = bsk_data.make_datastore_info( 'datastore', datastore_pubkey, driver_names=drivers )
    if 'error' in ds_info:
        raise Exception("make_datastore_info: {}".format(ds_info))

    res = bsk_data.put_datastore( rpc, ds_info, datastore_pk )
    if 'error' in res:
        raise Exception('put_datastore_info: {}'.format(res))

    # get back datastore
    ds_res = rpc.backend_datastore_get( datastore_id )
    if 'error' in ds_res:
        raise Exception('get_datastore: {}'.format(ds_res))

    return {'status': True, 'datastore': ds_res, 'datastore_id': datastore_id} 
   

def bsk_delete_datastore( session ):
    """
    Delete our data store.

    Return True on success
    Raise on error
    """

    # delete datastore with `DELETE http://localhost:{port}/v1/stores`

    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    # clear datastore 
    res = bsk_data.delete_datastore(rpc, datastore, APPLICATION_KEY)
    if 'error' in res:
        raise Exception( 'failed to delete datastore: {}'.format(res) )

    return True


def bsk_put_file( session, datastore, local_path, bsk_path ):
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

    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    res = bsk_data.datastore_putfile(rpc, datastore, bsk_path, data, APPLICATION_KEY)
    if 'error' in res:
        raise Exception('failed to put file: {}'.format(res))

    return True


def bsk_get_file( session, datastore, bsk_path, file=sys.stdout ):
    """
    Get the file data pointed to by {bsk_path} from the data store.
    Write it to stdout by default (override with file=)

    Return True on success
    Raise on error
    """

    # get the file with `GET http://localhost:{port}/v1/stores/{store ID}/files?path={bsk_path}`
    # get back raw data (application/octet-stream)
    
    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    res = bsk_data.datastore_getfile(rpc, datastore, bsk_path)
    if 'error' in res:
        raise Exception('failed to get file: {}'.format(res))

    print >> file, res['file']['idata']
    return True


def bsk_delete_file( session, datastore, bsk_path, port=6270 ):
    """
    Delete the file data pointed to by {bsk_path} from the data store.
    
    Return True on success
    Raise on error
    """
    
    # delete with `DELETE http://localhost:{port}/v1/stores/{store ID}/files?path={bsk_path)`
    # get back {'status': True}

    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    res = bsk_data.datastore_deletefile(rpc, datastore, bsk_path, APPLICATION_KEY)
    if 'error' in res:
        raise Exception("failed to delete file: {}".format(res))

    return True


def bsk_mkdir( session, datastore, bsk_path ):
    """
    Make a directory at {bsk_path} in the given data store

    Return True on success
    Raise on error
    """

    # make the directory with `POST http://localhost:{port}/v1/stores/{store ID}/directories?path={bsk_path}`
    # get back {'status': True} (http 200)

    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    res = bsk_data.datastore_mkdir(rpc, datastore, bsk_path, APPLICATION_KEY)
    if 'error' in res:
        raise Exception("failed to make directory: {}".format(res))
    
    return True


def bsk_listdir( session, datastore, bsk_path, file=sys.stdout ):
    """
    List a directory at {bsk_path} in the given data store.
    Write the listing to stdout.

    Return True on success
    Raise on error
    """

    # list the directory with `GET http://localhost:{port}/v1/stores/{store ID}/directories?path={bsk_path}`
    # get back the structured inode of the directory.
    # iterate through the inode's children and print their names and types (i.e. append '/' to directories)

    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    res = bsk_data.datastore_listdir(rpc, datastore, bsk_path)
    if 'error' in res:
        raise Exception("Failed to list directory: {}".format(res))

    dir_listing = res['dir']['idata']
    
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


def bsk_rmdir( session, datastore, bsk_path ):
    """
    Remove a directory at {bsk_path} in the given data store.
    
    Return True on success
    Raise on error
    """

    # delete the directory with `DELETE http://localhost:{port}/v1/stores/{store ID}/directories?path={bsk_path}`
    
    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    res = bsk_data.datastore_rmdir(rpc, datastore, bsk_path, APPLICATION_KEY)
    if 'error' in res:
        raise Exception("Failed to remove directory: {}".format(res))

    return True


def bsk_stat( session, datastore, bsk_path, port=6270 ):
    """
    Stat a file or directory

    Return the inode structure on success
    Raise on error
    """

    # send `GET http://localhost:{port}/v1/stores/{store ID}/inodes?path={bsk_path`

    rpc = bsk_rpc.local_api_connect(api_session=session)
    assert rpc

    res = bsk_data.datastore_stat(rpc, datastore, bsk_path)
    if 'error' in res:
        raise Exception("Failed to stat: {}".format(res))

    return res['inode_info']['inode']


if __name__ == '__main__':
    # unit tests!
    import StringIO

    api_password = sys.argv[1]
    ses = bsk_get_session(api_password)
    assert ses, "Failed to authentcate"

    datastore_res = bsk_make_datastore(ses, ['disk'])
    assert 'error' not in datastore_res, "Failed to make datastore"

    datastore = datastore_res['datastore']

    # load something 
    with open("/tmp/.footest", 'w') as f:
        f.write("hello world\x00\x01\x02\x03\x04")

    res = bsk_put_file(ses, datastore, "/tmp/.footest", "/foo")
    assert res, "Failed to put file"

    # get it back 
    sb = StringIO.StringIO()
    res = bsk_get_file(ses, datastore, "/foo", file=sb)
    assert res, "Failed to get file"
    assert sb.getvalue() == "hello world\x00\x01\x02\x03\x04\n", "Got wrong data ({})".format(sb.getvalue())

    # make a directory 
    res = bsk_mkdir(ses, datastore, "/bar")
    assert res, "Failed to mkdir"

    # list directory 
    sb = StringIO.StringIO()
    res = bsk_listdir(ses, datastore, "/", file=sb)
    assert res, "Failed to listdir"
    assert sb.getvalue() == "bar/\nfoo\n", "Got wrong dir ({})".format(sb.getvalue())

    # delete file 
    res = bsk_delete_file(ses, datastore, '/foo')
    assert res

    # delete directory 
    res = bsk_rmdir(ses, datastore, '/bar')
    assert res

    # delete datastore
    res = bsk_delete_datastore(ses)
    assert res

