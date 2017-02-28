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

import json
import sys
import os
import signal

from config import get_logger
log = get_logger('blockstack-client')

def exit_with_error(error_message, help_message=None):

    result = {'error': error_message}

    if help_message is not None:
        result['help'] = help_message
    print_result(result, file=sys.stderr)
    sys.exit(0)


def pretty_dump(data):
    """ format data
    """

    if type(data) is list:

        if len(data) == 0:
            # we got an empty array
            data = {}
        else:
            # Netstring server responds with [{data}]
            log.debug("converting [] to {}")
            data = data[0]

    if type(data) is not dict:
        try:
            data = json.loads(data)
        except Exception as e:
            # data is not valid json, convert to json
            data = {'result': data}

    return json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))


def pretty_print(data):

    try:
        data = data[0]
    except:
        pass

    if type(data) is not dict:
        try:
            data = json.loads(data)
        except Exception as e:
            log.debug("ERROR in pretty print: %s" % e)

    print pretty_dump(data)


def print_result(json_str, file=sys.stdout):
    data = pretty_dump(json_str)

    if data != "{}":
        print >> file, data


def satoshis_to_btc(satoshis):

    return satoshis * 0.00000001


def btc_to_satoshis(btc):

    return int(btc / 0.00000001)


def daemonize( logpath, child_wait=None ):
    """
    Double-fork and make a daemon.
    Have the intermediate child call child_wait()
    to block its exit until the child is "ready"
    (i.e. child_wait() returns)

    Return 0 if we're the daemon child
    Return >0 if we're the parent
    """
    logfile = open(logpath, 'a+')

    child_pid = os.fork()

    if child_pid == 0:
        # child!
        sys.stdin.close()
        os.dup2(logfile.fileno(), sys.stdout.fileno())
        os.dup2(logfile.fileno(), sys.stderr.fileno())
        os.setsid()

        daemon_pid = os.fork()
        if daemon_pid == 0:
            # daemon! chdir and return
            os.chdir('/')
            return 0

        elif daemon_pid > 0:
            # parent (intermediate child)
            # wait for child to fully initialize...
            res = True
            if child_wait is not None:
                res = child_wait()

            if res:
                sys.exit(0)
            else:
                sys.exit(1)

        else:
            # error
            sys.exit(1)

    elif child_pid > 0:
        # grand-parent (caller)
        # wait for intermediate child
        pid, status = os.waitpid(child_pid, 0)
        if os.WEXITSTATUS(status) == 0:
            return child_pid
        else:
            log.error("Child exit status {}".format(status))
            return -1
    
    else:
        # failed to fork 
        log.error("Failed to fork")
        return -1

    return 0
