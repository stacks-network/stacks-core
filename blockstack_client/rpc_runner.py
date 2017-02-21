#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

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

import os
import sys
import traceback
import config as blockstack_config
from rpc import local_api_start, local_api_stop, local_api_status, local_api_connect


if __name__ == '__main__':
    # running as a local API endpoint
    usage = '{} COMMAND PORT [config_path]'.format(sys.argv[0])

    try:
        command, portnum = sys.argv[1], int(sys.argv[2])
        config_dir = blockstack_config.CONFIG_DIR
        config_path = blockstack_config.CONFIG_PATH

        if len(sys.argv) > 3:
            config_dir = sys.argv[3]
            config_path = os.path.basename(blockstack_config.CONFIG_PATH)
            config_path = os.path.join(config_dir, config_path)
    except Exception as e:
        traceback.print_exc()
        print(usage, file=sys.stderr)
        sys.exit(1)

    passwd = os.environ.get('BLOCKSTACK_CLIENT_WALLET_PASSWORD', None)
    api_pass = os.environ.get("BLOCKSTACK_API_PASSWORD", None)
    
    if api_pass is None:
        # try to get it from the config file 
        conf = blockstack_config.get_config(config_path)
        assert conf 

        api_pass = conf['api_password']

    if command == 'start':
        assert passwd, "No wallet password given"
        assert api_pass, "No API password given"

        rc = local_api_start(port=portnum, config_dir=config_dir, api_pass=api_pass, password=passwd)
        if not rc:
            sys.exit(1)

        sys.exit(0)

    elif command == 'start-foreground':
        assert passwd, "No wallet password given"
        assert api_pass, "No API password given"

        rc = local_api_start(port=portnum, config_dir=config_dir, api_pass=api_pass, password=passwd, foreground=True)
        if not rc:
            sys.exit(1)

        sys.exit(0)

    elif command == 'status':
        rc = local_api_status(config_dir=config_dir)
        if rc:
            print('Alive', file=sys.stderr)
            sys.exit(0)
        else:
            print('Dead', file=sys.stderr)
            sys.exit(1)

    elif command == 'stop':
        rc = local_api_stop(config_dir=config_dir)
        sys.exit(0 if rc else 1)

    elif command == 'restart':
        rc = local_api_stop(config_dir=config_dir)
        if not rc:
            sys.exit(1)
        else:
            assert passwd, "No wallet password given"
            assert api_pass, "No API password given"
            rc = local_api_start(port=portnum, config_dir=config_dir, api_pass=api_pass, password=passwd)
            if not rc:
                sys.exit(1)

            sys.exit(0)
    else:
        print(usage, file=sys.stderr)
        sys.exit(1)
