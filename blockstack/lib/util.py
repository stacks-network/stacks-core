#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2018 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import json
import sys
import os
import urllib2
import hashlib
import threading
import traceback
import gc
import time
import resource
import jsonschema
import random
import sqlite3
import re
import signal
import keylib
import virtualchain
import virtualchain.lib.blockchain.bitcoin_blockchain as bitcoin_blockchain

from .config import RPC_SERVER_PORT, BLOCKSTACK_TEST, SUBDOMAIN_ADDRESS_VERSION_BYTE, SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE
from .schemas import *

log = virtualchain.get_logger()

def url_to_host_port(url, port=None):
    """
    Given a URL, turn it into (host, port) for a blockstack server.
    Return (None, None) on invalid URL
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    if not port:
        port = RPC_SERVER_PORT

    urlinfo = urllib2.urlparse.urlparse(url)
    hostport = urlinfo.netloc

    parts = hostport.split('@')
    if len(parts) > 2:
        return None, None

    if len(parts) == 2:
        hostport = parts[1]

    parts = hostport.split(':')
    if len(parts) > 2:
        return None, None

    if len(parts) == 2:
        try:
            port = int(parts[1])
            assert 0 < port and port < 65535, 'Invalid port'
        except TypeError:
            return None, None

    return parts[0], port


def url_protocol(url, port=None):
    """
    Get the protocol to use for a URL.
    return 'http' or 'https' or None
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        return None

    urlinfo = urllib2.urlparse.urlparse(url)
    assert urlinfo.scheme in ['http', 'https'], 'Invalid URL scheme in {}'.format(url)
    return urlinfo.scheme


def atlas_inventory_to_string( inv ):
    """
    Inventory to string (bitwise big-endian)
    """
    ret = ""
    for i in range(0, len(inv)):
        for j in range(0, 8):
            bit_index = 1 << (7 - j)
            val = (ord(inv[i]) & bit_index)
            if val != 0:
                ret += "1"
            else:
                ret += "0"

    return ret


def db_query_execute(cur, query, values, abort=True, max_timeout=300):
    """
    Safely execute a sqlite3 query by handling lock-conflicts and timing out correctly.
    Failure to do so will abort the program by default.
    """
    timeout = 1.0
    while True:
        try:
            ret = cur.execute(query, values)
            return ret
        except sqlite3.OperationalError as oe:
            if oe.message == "database is locked":
                timeout = min(max_timeout, timeout * 2 + timeout * random.random())
                log.error("Query timed out due to lock; retrying in %s: %s" % (timeout, db_format_query( query, values )))
                time.sleep(timeout)
            
            else:
                if abort:
                    log.exception(oe)
                    log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
                    log.error("\n".join(traceback.format_stack()))
                    os.abort()
                else:
                    raise oe

        except Exception, e:
            if abort:
                log.exception(e)
                log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
                log.error("\n".join(traceback.format_stack()))
                os.abort()
            else:
                raise e


def db_format_query( query, values ):
    """
    Turn a query into a string for printing.
    Useful for debugging.
    """
    return "".join( ["%s %s" % (frag, "'%s'" % val if type(val) in [str, unicode] else val) for (frag, val) in zip(query.split("?"), values + ("",))] )


def make_DID(name_type, address, index):
    """
    Standard way of making a DID.
    name_type is "name" or "subdomain"
    """
    if name_type not in ['name', 'subdomain']:
        raise ValueError("Require 'name' or 'subdomain' for name_type")

    if name_type == 'name':
        address = virtualchain.address_reencode(address)
    else:
        # what's the current version byte?
        vb = keylib.b58check.b58check_version_byte(address)
        if vb == bitcoin_blockchain.version_byte:
            # singlesig
            vb = SUBDOMAIN_ADDRESS_VERSION_BYTE
        else:
            vb = SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE

        address = virtualchain.address_reencode(address, version_byte=vb)

    return 'did:stack:v0:{}-{}'.format(address, index)


def parse_DID(did, name_type=None):
    """
    Given a DID string, parse it into {'address': ..., 'index': ..., 'name_type'}
    Raise on invalid DID
    """
    did_pattern = '^did:stack:v0:({}{{25,35}})-([0-9]+)$'.format(OP_BASE58CHECK_CLASS)

    m = re.match(did_pattern, did)
    assert m, 'Invalid DID: {}'.format(did)

    original_address = str(m.groups()[0])
    name_index = int(m.groups()[1])
    vb = keylib.b58check.b58check_version_byte(original_address)
    name_type = None

    if vb in [SUBDOMAIN_ADDRESS_VERSION_BYTE, SUBDOMAIN_ADDRESS_MULTISIG_VERSION_BYTE]:
        name_type = 'subdomain'

        # decode version 
        if vb == SUBDOMAIN_ADDRESS_VERSION_BYTE:
            vb = bitcoin_blockchain.version_byte
        else:
            vb = bitcoin_blockchain.multisig_version_byte

        original_address = virtualchain.address_reencode(original_address, version_byte=vb)

    else:
        name_type = 'name'
        original_address = virtualchain.address_reencode(original_address)

    return {'address': original_address, 'index': name_index, 'name_type': name_type}


def daemonize(logfile):
    """
    Double-fork and make a daemon.
    Have the intermediate child call child_wait()
    to block its exit until the child is "ready"
    (i.e. child_wait() returns)

    Return 0 if we're the daemon child
    Return >0 if we're the parent
    """
    
    # turn off GC across the fork
    gc.collect(2)
    gc.collect(1)
    gc.collect(0)
    gc.disable()
    
    child_pid = os.fork()

    if child_pid == 0:
        # child!
        sys.stdin.close()
        os.dup2(logfile.fileno(), sys.stdout.fileno())
        os.dup2(logfile.fileno(), sys.stderr.fileno())

        soft_num_open_files, hard_num_open_files = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard_num_open_files == resource.RLIM_INFINITY:
            # guess
            hard_num_open_files = 1024

        # we don't have many other fds open yet
        for i in range(3, hard_num_open_files):
            if i == logfile.fileno():
                continue

            try:
                os.close(i)
            except:
                pass

        os.setsid()

        daemon_pid = os.fork()
        if daemon_pid == 0:
            # daemon! chdir and return
            os.chdir('/')
            gc.enable()
            gc.collect(2)
            gc.collect(1)
            gc.collect(0)
            return 0

        elif daemon_pid > 0:
            # parent (intermediate child)
            sys.exit(0)

        else:
            # error
            sys.exit(1)

    elif child_pid > 0:
        # grand-parent (caller)
        # re-activate gc
        gc.enable()
        gc.collect(2)
        gc.collect(1)
        gc.collect(0)

        # wait for intermediate child.
        # panic if we don't hear back after 5 minutes
        timeout = 600
        if BLOCKSTACK_TEST:
            # wait around so we can attach gdb or whatever
            timeout = 60000

        for i in range(0, timeout):
            pid, status = os.waitpid(child_pid, os.WNOHANG)
            if pid == 0:
                # still waiting
                time.sleep(1)
                log.debug("Still waiting on {}".format(child_pid))
                continue

            # child has exited!
            if os.WEXITSTATUS(status) == 0:
                return child_pid
            else:
                log.error("Child exit status {}".format(status))
                return -1

        # child has not exited yet.  This is not okay.
        log.error("Child PID={} did not exit.  Killing it instead and failing...".format(child_pid))
        os.kill(child_pid, signal.SIGKILL)
        return -1
    
    else:
        # failed to fork 
        log.error("Failed to fork")
        return -1

    # parent! success
    return child_pid
