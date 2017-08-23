#!/usr/bin/env python2
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

if __name__ == "__main__":
    # unit tests!
    import blockstack_client
    import blockstack_client.actions
    import subprocess
    import requests
    from gaia import *

    blockstack_client.session()

    class CLIArgs(object):
        pass

    def get_session( blockchain_id, app_privkey, app_domain, api_methods, device_ids, public_keys, this_device_id='', config_path=CONFIG_PATH ):
        """
        sign in and get a token
        """
        args = CLIArgs()

        if blockchain_id:
            args.blockchain_id = blockchain_id
        else:
            args.blockchain_id = None

        args.app_domain = app_domain
        args.api_methods = ','.join(api_methods)
        args.privkey = app_privkey

        device_ids = ','.join(device_ids)
        public_keys = ','.join(public_keys)
        args.device_ids = device_ids
        args.public_keys = public_keys
        args.this_device_id = this_device_id

        res = blockstack_client.actions.cli_app_signin( args, config_path=config_path )
        if 'error' in res:
            raise Exception("Error: {}".format(res['error']))
        else:
            return res['token']

    datastore_pk = keylib.ECPrivateKey().to_hex()
    datastore_pubk = get_pubkey_hex(datastore_pk)
    datastore_id = datastore_get_id(datastore_pubk)
    this_device_id = get_local_device_id(config_dir=os.path.dirname(CONFIG_PATH))

    other_pks = [keylib.ECPrivateKey().to_hex() for _ in xrange(1, 3)]
    other_pubks = [get_pubkey_hex(pk) for pk in other_pks]
    other_device_ids = [this_device_id + '-{}'.format(i) for i in xrange(1, 3)]

    all_device_ids = [this_device_id] + other_device_ids
    all_device_privkeys = [datastore_pk] + other_pks
    all_device_pubkeys = [datastore_pubk] + other_pubks
    all_sessions = []
    all_rpcs = []

    conf = get_config()
    assert conf
    
    for i in xrange(0, len(all_device_ids)):
        # authenticate each device
        ses = get_session(None, all_device_privkeys[i], 'http://localhost:8888', ['store_write'], all_device_ids, all_device_pubkeys, this_device_id=all_device_ids[i])

        rpc = blockstack_client.rpc.local_api_connect(api_session=ses)
        assert rpc

        all_sessions.append(ses)
        all_rpcs.append(rpc)
    
    # create the datastore
    rpc = all_rpcs[0]
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

    datastore = ds_res['datastore']

    data_pubkeys = [{'device_id': this_device_id, 'public_key': datastore_pubk}] + [{'device_id': other_dev_id, 'public_key': other_pubk} for (other_dev_id, other_pubk) in zip(other_device_ids, other_pubks)]

    # do this all twice
    for i in xrange(0, 2):
        
        # put a file from each device
        for i in xrange(0, len(all_device_ids)):
            dev_id = all_device_ids[i]
            data_pkey = all_device_privkeys[i]
            file_name = 'hello_world-{}'.format(i)
            file_data = 'hello world {}\x00\x01\x02\x03\x04\x05'.format(i)
            rpc = all_rpcs[i]

            res = datastore_putfile(rpc, datastore, file_name, file_data, data_pkey, data_pubkeys, this_device_id=dev_id, synchronous=True)
            if 'error' in res:
                print 'datastore_putfile {}: {}'.format(file_name, res)
                sys.exit(1)

        res = rpc.backend_datastore_get_root(None, datastore, data_pubkeys)
        if 'error' in res:
            print 'datastore_get_root /: {}'.format(res)
            sys.exit(1)
        
        root = res['root']

        # sanity check 
        for i in xrange(0, len(all_device_ids)):
            file_name = 'hello_world-{}'.format(i)
            if file_name not in root:
                print 'root is {}'.format(res)
                sys.exit(1)

        # get/delete
        for i in xrange(0, len(all_device_ids)):
            file_name = 'hello_world-{}'.format(i)
            file_data = 'hello world {}\x00\x01\x02\x03\x04\x05'.format(i)
            data_pkey = all_device_privkeys[i]
            dev_id = all_device_ids[i]
            rpc = all_rpcs[i]
            
            print ""
            print file_name
            print ""

            res = datastore_getfile(rpc, None, datastore, file_name, data_pubkeys)
            if 'error' in res:
                print 'getfile failed: {}'.format(res)
                sys.exit(1)

            # sanity check
            if res['data'] != file_data:
                print 'datastore_getfile {}: {}'.format(file_name, res)
                sys.exit(1)
            
            # stat 
            res = datastore_stat(rpc, None, datastore, file_name, data_pubkeys, dev_id)
            if 'error' in res:
                print 'datastore_stat {}: {}'.format(file_name, res)
                sys.exit(1)

            # should fail
            res = delete_datastore(rpc, datastore, data_pkey, data_pubkeys)
            if 'error' not in res:
                print 'deleted datastore: {}'.format(res)
                sys.exit(1)

            if res['errno'] != "ENOTEMPTY":
                print 'wrong errno on ENOTEMPTY delete datastore: {}'.format(res)
                sys.exit(1)

            res = datastore_deletefile(rpc, datastore, file_name, data_pkey, data_pubkeys, this_device_id=dev_id, synchronous=True)
            if 'error' in res:
                print 'datastore_deletefile: {}'.format(res)
                sys.exit(1)

            # sanity check 
            res = rpc.backend_datastore_get_root(None, datastore, data_pubkeys)
            if 'error' in res:
                print 'datastore_get_root /: {}'.format(res)
                sys.exit(1)

            if file_name in res['root']:
                print '{} still present'.format(file_name)
                print res['root']
                sys.exit(1)

            # sanity check
            res = datastore_getfile(rpc, None, datastore, file_name, data_pubkeys)
            if 'error' in res:
                if not res.has_key('errno') or res['errno'] != "ENOENT":
                    print 'getfile failed wrong: {}'.format(res)
                    sys.exit(1)
        
            else:
                print 'accidentally succeeded to getfile: {}'.format(res)
                sys.exit(1)
 
            # stat 
            res = datastore_stat(rpc, None, datastore, file_name, data_pubkeys, dev_id)
            if 'error' in res:
                if not res.has_key('errno') or res['errno'] != "ENOENT":
                    print 'datastore_stat failed wrong on {}: {}'.format(file_name, res)
                    sys.exit(1)

            else:
                print 'accidentally succeeded to stat {}'.format(file_name)
                sys.exit(1)


    # clear datastore 
    res = delete_datastore(rpc, datastore, datastore_pk, data_pubkeys)
    
    if 'error' in res:
        print 'failed to delete empty datastore: {}'.format(res)
        sys.exit(1)

    sys.exit(0)

