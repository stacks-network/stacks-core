#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore daemon common infrastructure.
    Shared by:
    * blockstored
    * blockmirrord
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import argparse
import coinkit
import logging
import os
import os.path
import sys
import subprocess
import signal
import json
import datetime
import traceback
import httplib
import ssl
import threading
import time
import socket
from multiprocessing import Pool

import config
import cache 
from utilitybelt import is_valid_int

from . import get_nameops_in_block, get_nameops_in_blocks, build_nameset, NameDb

create_ssl_authproxy = False 
do_wrap_socket = False

if hasattr( ssl, "_create_unverified_context" ):
   ssl._create_default_https_context = ssl._create_unverified_context
   create_ssl_authproxy = True 

if not hasattr( ssl, "create_default_context" ):
   create_ssl_authproxy = False
   do_wrap_socket = True

log = logging.getLogger()
log.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' if config.DEBUG else '%(message)s')
formatter = logging.Formatter( log_format )
console.setFormatter(formatter)
log.addHandler(console)

from bitcoinrpc.authproxy import AuthServiceProxy

bitcoin_opts = {
   "bitcoind_user": config.BITCOIND_USER,
   "bitcoind_passwd": config.BITCOIND_PASSWD,
   "bitcoind_server": config.BITCOIND_SERVER,
   "bitcoind_port": config.BITCOIND_PORT,
   "bitcoind_use_https": config.BITCOIND_USE_HTTPS
}


class BitcoindConnection( httplib.HTTPSConnection ):
   """
   Wrapped SSL connection, if we can't use SSLContext.
   """

   def __init__(self, host, port, timeout=None ):
   
      httplib.HTTPSConnection.__init__(self, host, port )
      self.timeout = timeout
        
   def connect( self ):
      
      sock = socket.create_connection((self.host, self.port), self.timeout)
      if self._tunnel_host:
         self.sock = sock
         self._tunnel()
         
      self.sock = ssl.wrap_socket( sock, cert_reqs=ssl.CERT_NONE )
      

def create_bitcoind_connection(
        rpc_username=None,
        rpc_password=None,
        server=None,
        port=None,
        use_https=None ):
    """ creates an auth service proxy object, to connect to bitcoind
    """
    
    global bitcoin_opts, do_wrap_socket, create_ssl_authproxy
    
    if rpc_username is None:
        rpc_username = bitcoin_opts.get( "bitcoind_user" )
    
    if rpc_password is None:
        rpc_password = bitcoin_opts.get( "bitcoind_passwd" )
    
    if server is None:
        server = bitcoin_opts.get( "bitcoind_server" )
        
    if port is None:
        port = bitcoin_opts.get( "bitcoind_port" )
    
    if use_https is None:
        use_https = bitcoin_opts.get( "bitcoind_use_https" )
        
    log.debug("[%s] Connect to bitcoind at %s://%s@%s:%s" % (os.getpid(), 'https' if use_https else 'http', rpc_username, server, port) )
    
    protocol = 'https' if use_https else 'http'
    if not server or len(server) < 1:
        raise Exception('Invalid bitcoind host address.')
    if not port or not is_valid_int(port):
        raise Exception('Invalid bitcoind port number.')
    
    authproxy_config_uri = '%s://%s:%s@%s:%s' % (protocol, rpc_username, rpc_password, server, port)
    
    if do_wrap_socket:
       # ssl._create_unverified_context and ssl.create_default_context are not supported.
       # wrap the socket directly 
       connection = BitcoindConnection( server, int(port) )
       return AuthServiceProxy(authproxy_config_uri, connection=connection)
       
    elif create_ssl_authproxy:
       # ssl has _create_unverified_context, so we're good to go 
       return AuthServiceProxy(authproxy_config_uri)
    
    else:
       # have to set up an unverified context ourselves 
       ssl_ctx = ssl.create_default_context()
       ssl_ctx.check_hostname = False
       ssl_ctx.verify_mode = ssl.CERT_NONE
       connection = httplib.HTTPSConnection( server, int(port), context=ssl_ctx )
       return AuthServiceProxy(authproxy_config_uri, connection=connection)


def get_working_dir( working_dir ):

    from os.path import expanduser
    home = expanduser("~")
    
    working_dir = os.path.join(home, working_dir)

    if not os.path.exists(working_dir):
        os.makedirs(working_dir)

    return working_dir


def get_config_file( working_dir, config_file ):
    working_dir = get_working_dir( working_dir )
    return os.path.join(working_dir, config_file )


from ConfigParser import SafeConfigParser


def prompt_user_for_bitcoind_details( working_dir, config_file ):
    """
    """
    config_file = get_config_file( working_dir, config_file )
    parser = SafeConfigParser()

    parser.read(config_file)

    if not parser.has_section('bitcoind'):

        bitcoind_server = raw_input(
            "Enter bitcoind host address (default: 127.0.0.1): "
            ) or '127.0.0.1'
        bitcoind_port = raw_input(
            "Enter bitcoind rpc port (default: 8332): ") or '8332'
        bitcoind_user = raw_input("Enter bitcoind rpc user/username: ")
        bitcoind_passwd = raw_input("Enter bitcoind rpc password: ")
        use_https = raw_input("Is ssl enabled on bitcoind? (yes/no): ")

        if not parser.has_section('bitcoind'):
            parser.add_section('bitcoind')

        parser.set('bitcoind', 'server', bitcoind_server)
        parser.set('bitcoind', 'port', bitcoind_port)
        parser.set('bitcoind', 'user', bitcoind_user)
        parser.set('bitcoind', 'passwd', bitcoind_passwd)
        parser.set('bitcoind', 'use_https', use_https)

        fout = open(config_file, 'w')
        parser.write(fout)

        if use_https.lower() == "yes" or use_https.lower() == "y":
            bitcoind_use_https = True
        else:
            bitcoind_use_https = False

        return create_bitcoind_connection(bitcoind_user, bitcoind_passwd,
                                          bitcoind_server, bitcoind_port,
                                          bitcoind_use_https)

    else:
        parser.remove_section('bitcoind')
        fout = open(config_file, 'w')
        parser.write(fout)
        return create_bitcoind_connection()


def refresh_index( bitcoind, first_block, last_block, working_dir, initial_index=False):
    """
    """

    import workpool
    
    working_dir = get_working_dir( working_dir )

    namespace_file = os.path.join( working_dir, config.BLOCKSTORED_NAMESPACE_FILE)
    snapshots_file = os.path.join( working_dir, config.BLOCKSTORED_SNAPSHOTS_FILE)
    lastblock_file = os.path.join( working_dir, config.BLOCKSTORED_LASTBLOCK_FILE)

    start = datetime.datetime.now()
    
    num_workers = config.MULTIPROCESS_NUM_WORKERS
    nameop_sequence = []
    
    # feed workers bitcoind this way
    workpool.multiprocess_bitcoind_factory( create_bitcoind_connection )
    
    workpool = Pool( processes=num_workers )
    
    # get *all* the block nameops!
    nameop_sequence = get_nameops_in_blocks( workpool, range(first_block, last_block+1) )
    workpool.close()
    workpool.join()
    nameop_sequence.sort()
    
    time_taken = "%s seconds" % (datetime.datetime.now() - start).seconds
    log.info(time_taken)

    db = get_namedb()
    merkle_snapshot = build_nameset(db, nameop_sequence)
    db.save_names(namespace_file)
    db.save_snapshots(snapshots_file)

    merkle_snapshot = "merkle snapshot: %s\n" % merkle_snapshot
    log.info(merkle_snapshot)
    log.info(db.name_records)

    fout = open(lastblock_file, 'w')  # to overwrite
    fout.write(str(last_block))
    fout.close()
    

def get_index_range( bitcoind, working_dir, start_block=0):
    """
    """

    from config import FIRST_BLOCK_MAINNET

    if start_block == 0:
        start_block = FIRST_BLOCK_MAINNET

    try:
        current_block = int(bitcoind.getblockcount())
        
    except Exception, e:
        log.exception(e)
        log.info("ERROR: Cannot connect to bitcoind")
        log.info("Please check your bitcoind configuration")
        exit(1)

    working_dir = get_working_dir(working_dir)
    lastblock_file = os.path.join(working_dir, config.BLOCKSTORED_LASTBLOCK_FILE)

    saved_block = 0
    if os.path.isfile(lastblock_file):
         
        with open(lastblock_file, 'r') as fin:
           try:
              saved_block = fin.read()
              saved_block = int(saved_block)
           except:
              log.msg("Corrupt lastblock")
              saved_block = 0
              try:
                 os.unlink(lastblock_file)
              except OSError, oe:
                 pass 
              
              pass 

    if saved_block == 0:
        pass
    elif saved_block == current_block:
        start_block = saved_block
    elif saved_block < current_block:
        start_block = saved_block + 1

    return start_block, current_block


def init_bitcoind( working_dir, config_file ):
    """
    """

    config_file = get_config_file( working_dir, config_file )
    parser = SafeConfigParser()

    parser.read(config_file)

    if parser.has_section('bitcoind'):
        try:
            return create_bitcoind_connection()
        except Exception, e:
            log.exception(e)
            return prompt_user_for_bitcoind_details( working_dir, config_file )
        else:
            pass
    else:
        user_input = raw_input("Do you have your own bitcoind server? (yes/no): ")
        if user_input.lower() == "yes" or user_input.lower() == "y":
            return prompt_user_for_bitcoind_details( working_dir, config_file )
        else:
            log.info("Using default bitcoind server at %s", config.BITCOIND_SERVER)
            return create_bitcoind_connection()


def parse_bitcoind_args( return_parser=False ):
    """
    Get bitcoind command-line arguments.
    Optionally return the parser as well.
    """
    
    global bitcoin_opts
    
    bitcoin_opts = {
      "bitcoind_user": config.BITCOIND_USER,
      "bitcoind_passwd": config.BITCOIND_PASSWD,
      "bitcoind_server": config.BITCOIND_SERVER,
      "bitcoind_port": config.BITCOIND_PORT,
      "bitcoind_use_https": config.BITCOIND_USE_HTTPS
    }

    parser = argparse.ArgumentParser(
        description='Blockstore Core Daemon version {}'.format(config.VERSION))

    parser.add_argument(
        '--bitcoind-server',
        help='the hostname or IP address of the bitcoind RPC server')
    parser.add_argument(
        '--bitcoind-port', type=int,
        help='the bitcoind RPC port to connect to')
    parser.add_argument(
        '--bitcoind-user',
        help='the username for bitcoind RPC server')
    parser.add_argument(
        '--bitcoind-passwd',
        help='the password for bitcoind RPC server')
    parser.add_argument(
        "--bitcoind-use-https", action='store_true',
        help='use HTTPS to connect to bitcoind')
    
    args, _ = parser.parse_known_args()

    # propagate options 
    for (argname, config_name) in zip( ["bitcoind_server", "bitcoind_port", "bitcoind_user", "bitcoind_passwd"], \
                                       ["BITCOIND_SERVER", "BITCOIND_PORT", "BITCOIND_USER", "BITCOIND_PASSWD"] ):
        
        if hasattr( args, argname ) and getattr( args, argname ) is not None:
            
            bitcoin_opts[ argname ] = getattr( args, argname )
            setattr( config, config_name, getattr( args, argname ) )
    
    if hasattr( args, "bitcoind_use_https" ):
        if args.bitcoind_use_https:
            
            config.BITCOIND_USE_HTTPS = True 
            bitcoin_opts[ "bitcoind_use_https" ] = True
       
    if return_parser:
       return bitcoin_opts, parser 
    else:
       return bitcoin_opts
    