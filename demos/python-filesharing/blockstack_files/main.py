#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
This code is public domain.
Used as a demo for Bockstack.
"""

import sys
import os
import json
import argparse
import traceback

from .bsk import *
from .version import __version__

CONFIG_PATH = os.path.expanduser('~/.blockstack_files.conf')
DRIVERS = ['disk']

def load_datastore_info( config_path=CONFIG_PATH ):
    """
    Get our config.
    Returns {
        'session': session,
        'datastore_id': datastore ID
    }

    Or, returns None if there's no such file.
    Raise on exception.
    """

    if not os.path.exists(config_path):
        return None

    with open(config_path, 'r') as f:
        dat = f.read().strip()
        conf = json.loads(dat)
        return conf


def store_datastore_info( session, datastore_id, config_path=CONFIG_PATH ):
    """
    Store our config.
    Return True on success
    Raise on error
    """
    conf = {
        'session': session,
        'datastore_id': datastore_id
    }

    with open(config_path, 'w') as f:
        f.write( json.dumps(conf) )

    return True


def login( api_password=None, drivers=DRIVERS, config_path=CONFIG_PATH ):
    """
    Authenticate to Blockstack,
    get a session, and create the 
    datastore if it doesn't exist already.

    Store the session and datastore ID to disk.

    Returns {'session': session, 'datastore_id': ...} on success
    Returns None on error
    """

    creds = load_datastore_info( config_path=config_path )
    if creds is not None:
        return creds

    assert api_password, 'API password required'
    
    # first-time signing in
    session = bsk_get_session( api_password )
    datastore_id = bsk_make_datastore( session, drivers=drivers )

    store_datastore_info( session, datastore_id, config_path=config_path )

    return {'session': session, 'datastore_id': datastore_id}


def logout( config_path=CONFIG_PATH ):
    """
    Remove our cached credentials.
    Return True on success
    Raise on error
    """
    if os.path.exists(config_path):
        os.unlink(config_path)

    return True


def run_cli( argv ):
    """
    Run the CLI.
    Return True on success
    Return False on error
    """
    argparser = argparse.ArgumentParser(description="blockstack-files version {}".format(__version__))
    subparsers = argparser.add_subparsers(
        dest='action', help='the action to be taken')

    # ---------------------------
    subparser = subparsers.add_parser(
        'login', help='authenticate and log into your Blockstack node')

    subparser.add_argument(
        'api_password', action='store', help='Blockstack API password')

    # ---------------------------
    subparser = subparsers.add_parser(
        'logout', help='log out of your Blockstack node')

    # ---------------------------
    subparser = subparsers.add_parser(
        'ls', help='list a given directory')

    subparser.add_argument(
        'path', action='store', help='the path to the directory to list')

    # ---------------------------
    subparser = subparsers.add_parser(
        'cat', help='cat a file to stdout')

    subparser.add_argument(
        'path', action='store', help='the path to the file to read')

    # ---------------------------
    subparser = subparsers.add_parser(
        'mkdir', help='make a directory')

    subparser.add_argument(
        'path', action='store', help='the path to the directory to create')

    # ---------------------------
    subparser = subparsers.add_parser(
        'put', help='store a file')

    subparser.add_argument(
        'local_path', action='store', help='the path to the local data on disk')

    subparser.add_argument(
        'path', action='store', help='the path in the data store to host this data')

    # ---------------------------
    subparser = subparsers.add_parser(
        'rm', help='remove a file')

    subparser.add_argument(
        'path', action='store', help='the path to the file to delete')

    # ---------------------------
    subparser = subparsers.add_parser(
        'rmdir', help='remove a directory')

    subparser.add_argument(
        'path', action='store', help='the path to the directory to remove.')


    # act on it
    args = argparser.parse_args()
   
    try:
        # authenticate, or get credentials
        if args.action == 'login':
            creds = login( args.api_password )

        else:
            try:
                creds = login()
            except:
                print >> sys.stderr, 'Unable to log in.  Try `{} login`'.format(argv[0])
                return False

        # bsk paths must be absolute 
        path = getattr(args, 'path', None)
        if path:
            if not path.startswith('/'):
                print >> sys.stderr, "Error: {} is not absolute".format(path)
                return False

        session = creds['session']
        datastore_id = creds['datastore_id']

        if args.action == 'ls':
            res = bsk_stat( session, datastore_id, path )
            if res['type'] == 2:
                bsk_listdir( session, datastore_id, path )
            else:
                print os.path.basename(path)

        elif args.action == 'cat':
            bsk_get_file( session, datastore_id, path )

        elif args.action == 'mkdir':
            bsk_mkdir( session, datastore_id, path )

        elif args.action == 'put':
            bsk_put_file( session, datastore_id, args.local_path, path )

        elif args.action == 'rm':
            bsk_delete_file( session, datastore_id, path )

        elif args.action == 'rmdir':
            bsk_rmdir( session, datastore_id, path )

        elif args.action == 'logout':
            logout()

        else:
            return False

        return True

    except Exception as e:
        traceback.print_exc()
        return False

