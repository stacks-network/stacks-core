#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import config as blockstack_config
from rpc import local_rpc_start, local_rpc_stop

if __name__ == "__main__":

    # running as a local API endpoint
    usage = "%s COMMAND PORT [config_path]" % sys.argv[0] 
    try:
        command = sys.argv[1]
        portnum = int(sys.argv[2])
        config_dir = blockstack_config.CONFIG_DIR
        config_path = blockstack_config.CONFIG_PATH 

        if len(sys.argv) > 3:
            config_dir = sys.argv[3]
            config_path = os.path.join(config_dir, os.path.basename(blockstack_config.CONFIG_PATH))

    except Exception, e:
        traceback.print_exc()
        print >> sys.stderr, usage
        sys.exit(1)

    if command == 'start':

        # maybe inherited password through the environment?
        passwd = os.environ.get("BLOCKSTACK_CLIENT_WALLET_PASSWORD", None)
        rc = local_rpc_start( portnum, config_dir=config_dir, password=passwd )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)
       
    elif command == 'start-foreground':
       
        passwd = os.environ.get("BLOCKSTACK_CLIENT_WALLET_PASSWORD", None)
        rc = local_rpc_start( portnum, config_dir=config_dir, foreground=True, password=passwd )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)

    elif command == 'status':
        rc = local_rpc_status( config_dir=config_dir )
        if rc:
            print >> sys.stderr, "Alive"
            sys.exit(0)
        else:
            print >> sys.stderr, "Dead"
            sys.exit(1)

    elif command == 'stop':
        rc = local_rpc_stop( config_dir=config_dir )
        if rc:
            sys.exit(0)
        else:
            sys.exit(1)

    elif command == 'restart':
       
        rc = local_rpc_stop( config_dir=config_dir )
        if not rc:
            sys.exit(1)
        else:

            rc = local_rpc_start( portnum, config_dir=config_dir )
            if rc:
                sys.exit(0)
            else:
                sys.exit(1)


