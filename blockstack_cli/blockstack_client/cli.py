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
    along with Blockstack-client.  If not, see <http://www.gnu.org/licenses/>.
"""

"""
IMPROTANT: READ THIS FIRST

Do NOT add CLI commands to this file.
Instead, define the appropriate method in the `actions.py` file
in this module.

This module will load and register each appropriate method from `actions.py`
as a command-line option.
"""

import argparse
import sys
import json
import traceback
import os
import re
import pybitcoin
import subprocess
from socket import error as socket_error
from time import sleep
from getpass import getpass

import requests
requests.packages.urllib3.disable_warnings()

import logging
logging.disable(logging.CRITICAL)

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from blockstack_client import config
from blockstack_client.client import session
from blockstack_client.config import WALLET_PATH, WALLET_PASSWORD_LENGTH, CONFIG_PATH
from blockstack_client.parser import parse_methods, build_method_subparsers

import blockstack_client.actions as builtin_methods

from pybitcoin import is_b58check_address

from binascii import hexlify

from wallet import *
from utils import exit_with_error, pretty_dump, print_result

log = config.get_logger()

def get_methods(prefix, module):
    """
    Get the built-in CLI methods
    """
    methods = []
    for attr in dir(module):
        if attr.startswith(prefix):
            method = getattr(module, attr)
            if callable(method) or hasattr(method, '__call__'):
                methods.append( method )

    return methods


def get_plugin_methods( module_name, prefix ):
    """
    Load methods from a given module
    Return the list on success
    Return None on error
    """
    try:
        mod = __import__(module_name)
    except ImportError:
        log.error("Failed to import '%s'" % module_name)
        return None 

    return get_methods( prefix, mod )
     

def get_cli_basic_methods():
    """
    Get the basic built-in CLI methods
    """
    return get_methods("cli_", builtin_methods )


def get_cli_advanced_methods():
    """
    Get the advanced usage built-in CLI methods
    """
    return get_methods("cli_advanced_", builtin_methods )


def run_cli(argv=None, config_path=CONFIG_PATH):
    """
    Run a CLI command from arguments (defaults to sys.argv)
    Return the result of the command on success.
    The result will be a dict, and will have 'error' defined on error condition.
    """

    if argv is None:
        argv = sys.argv

    print "\n%s\n" % argv
    conf = config.get_config(path=config_path)

    if conf is None:
        return {'error': 'Failed to load config'}

    advanced_mode = conf['advanced_mode']

    parser = argparse.ArgumentParser(
            description='Blockstack cli version {}'.format(config.VERSION))

    all_methods = []
    subparsers = parser.add_subparsers(dest='action')
    
    # add basic methods 
    basic_methods = get_cli_basic_methods()
    basic_method_info = parse_methods( basic_methods )
    build_method_subparsers( subparsers, basic_method_info )

    all_methods = basic_method_info 

    if advanced_mode:
        # add advanced methods 
        advanced_methods = get_cli_advanced_methods()
        advanced_method_info = parse_methods( advanced_methods )
        build_method_subparsers( subparsers, advanced_method_info )
        all_methods += advanced_method_info

    # Print default help message, if no argument is given
    if len(argv) == 1:
        parser.print_help()
        return {}

    args, unknown_args = parser.parse_known_args(args=argv[1:])
    result = {}

    blockstack_server = conf['server']
    blockstack_port = conf['port']

    # initialize blockstack connection
    session(conf=conf, server_host=blockstack_server,
            server_port=blockstack_port, set_global=True)

    # dispatch to the apporpriate method  
    for method_info in all_methods:
        if args.action != method_info['command']:
            continue

        method = method_info['method']
        result = method( args, config_path=config_path )
        
        return result

    # not found 
    return {'error': "No such command '%s'" % args.action}


if __name__ == '__main__':
    result = run_cli()
    if 'error' in result:
        exit_with_error(result['error'])
    else:
        print_result(result)
        sys.exit(0)


