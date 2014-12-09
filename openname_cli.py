#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Opennamed
    ~~~~~
    :copyright: (c) 2014 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import argparse
import sys
import json

import zerorpc
import config

c = zerorpc.Client(timeout=5)
c.connect('tcp://' + config.OPENNAMED_SERVER + ':' + config.OPENNAMED_PORT)

import logging 

log = logging.getLogger()
log.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
log.addHandler(console)

def pretty_dump(input):
    """ pretty dump
    """
    return json.dumps(input, sort_keys=False, indent=4, separators=(',', ': '))

def run_cli():
    """ run cli
    """
    parser = argparse.ArgumentParser(
        description='Openname Cli version {}'.format(config.VERSION))

    parser.add_argument(
        '--opennamed-server',
        help="""the hostname or IP address of the opennamed RPC server (default: {})""".format(config.OPENNAMED_SERVER))
    parser.add_argument(
        '--opennamed-port', type=int,
        help="""the opennamed RPC port to connect to (default: {})""".format(config.OPENNAMED_PORT))
    
    subparsers = parser.add_subparsers(
        dest='action', help='the action to be taken')

    parser_cli = subparsers.add_parser(
        'getinfo', help='get basic info from the opennamed server')
    parser_cli = subparsers.add_parser(
        'name_show', help='<name> display value of a registered name')

    #print default help message, if no argument is given
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.action == 'getinfo':
        try:
            log.info(pretty_dump(c.getinfo()))
        except Exception as e:
            log.info("Couldn't connect to opennamed server")
            exit(0)
    elif args.action == 'name_show':
        log.info('in name_show')
        #name_show code here

if __name__ == '__main__':
    run_cli()
