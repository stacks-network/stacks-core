#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org

    This file is part of Blockstack-client.

    Blockstack-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

from gaia import *

if __name__ == "__main__":
    # unit tests!
    import blockstack_client
    import subprocess
    import requests

    blockstack_client.session()

    class CLIArgs(object):
        pass

    def get_session( blockchain_id, app_privkey, app_domain, api_methods, device_ids, public_keys, config_path=CONFIG_PATH ):
        """
        sign in and get a token
        """
        args = CLIArgs()

        args.blockchain_id = blockchain_id
        args.app_domain = app_domain
        args.api_methods = ','.join(api_methods)
        args.privkey = app_privkey

        device_ids = ','.join(device_ids)
        public_keys = ','.join(public_keys)
        args.device_ids = device_ids
        args.public_keys = public_keys

        res = blockstack_client.cli_app_signin( args, config_path=config_path )
        if 'error' in res:
            raise Exception("Error: {}".format(res['error']))
        else:
            return res['token']

    datastore_pk = keylib.ECPrivateKey().to_hex()
    datastore_pubk = get_pubkey_hex(datastore_pk)
    datastore_id = datastore_get_id(datastore_pubk)
    this_device_id = '0'

    conf = get_config()
    assert conf

    ses = get_session(None, datastore_pk, 'foo.com.x', ['store_write'], [this_device_id], [datastore_pubk])

    rpc = blockstack_client.rpc.local_api_connect(api_session=ses)
    assert rpc

    # authenticate 
    ds_info = make_datastore_info("datastore", datastore_pubk, [this_device_id], driver_names=['disk'])
    if 'error' in ds_info:
        print "make_datastore_info: {}".format(ds_info)
        sys.exit(1)

    res = put_datastore( rpc, ds_info, datastore_pk )
    if 'error' in res:
        print 'put_datastore_info: {}'.format(res)
        sys.exit(1)

    ds_res = rpc.backend_datastore_get( None, None, datastore_id, device_ids=[this_device_id] )
    if 'error' in ds_res:
        print 'get_datastore: {}'.format(ds_res)
        sys.exit(1)

    datastore = ds_res

    data_pubkeys = [{'device_id': this_device_id, 'public_key': datastore_pubk}]

    # do this all twice
    for i in xrange(0, 2):
        
        res = datastore_putfile(rpc, datastore, 'hello_world', 'hello world\x00\x01\x02\x04\x05', datastore_pk, data_pubkeys, this_device_id=this_device_id, synchronous=True)
        if 'error' in res:
            print 'datastore_putfile: {}'.format(res)
            sys.exit(1)

        res = rpc.backend_datastore_get_root(None, datastore, data_pubkeys)
        if 'error' in res:
            print 'datastore_get_root /: {}'.format(res)
            sys.exit(1)

        # sanity check 
        if 'hello_world' not in res['root']:
            print 'root is {}'.format(res['root'])
            sys.exit(1)

        res = datastore_getfile(rpc, None, datastore, 'hello_world', data_pubkeys)
        if 'error' in res:
            print 'getfile failed: {}'.format(res)
            sys.exit(1)

        # sanity check
        if res['data'] != 'hello world\x00\x01\x02\x03\x04\x05':
            print 'datastore_getfile /dir1/dir2/hello: {}'.format(res)
            sys.exit(1)

        # should fail
        res = delete_datastore(rpc, datastore, datastore_pk)
        if 'error' not in res:
            print 'deleted datastore: {}'.format(res)
            sys.exit(1)

        if res['errno'] != errno.ENOTEMPTY:
            print 'wrong errno on ENOTEMPTY delete datastore: {}'.format(res)
            sys.exit(1)

        res = datastore_deletefile(rpc, datastore, 'hello_world', datastore_privk, data_pubkeys, this_device_id=this_device_id, synchronous=True)
        if 'error 'in res:
            print 'datastore_deletefile: {}'.format(res)
            sys.exit(1)

        # sanity check 
        res = rpc.backend_datastore_get_root(None, datastore, data_pubkeys)
        if 'error' in res:
            print 'datastore_get_root /: {}'.format(res)
            sys.exit(1)

        if 'hello_world' in res['root']:
            print 'hello_world still present'
            print res['root']
            sys.exit(1)

        # sanity check
        res = datastore_getfile(rpc, None, datastore, 'hello_world', data_pubkeys)
        if 'error' in res:
            if not res.has_key('errno') or res['errno'] != errno.ENOENT:
                print 'getfile failed: {}'.format(res)
                sys.exit(1)
        
        else:
            print 'accidentally succeeded to getfile: {}'.format(res)
            sys.exit(1)

    # clear datastore 
    res = delete_datastore(rpc, datastore, datastore_pk)
    if 'error' in res:
        print 'failed to delete empty datastore: {}'.format(res)
        sys.exit(1)

    sys.exit(0)

