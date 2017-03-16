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

import requests
requests.packages.urllib3.disable_warnings()

import logging
logging.disable(logging.CRITICAL)

from blockstack_client import config
from blockstack_client.client import session, analytics_user_register 
from blockstack_client.config import CONFIG_PATH, VERSION, semver_match, get_config, client_uuid_path, get_or_set_uuid
from blockstack_client.method_parser import parse_methods, build_method_subparsers

from wallet import *
from utils import exit_with_error, print_result

log = config.get_logger()


def get_methods(prefix, module):
    """
    Get the built-in CLI methods
    """
    methods = []
    for attr in dir(module):
        if not attr.startswith(prefix):
            continue

        method = getattr(module, attr)

        if callable(method) or hasattr(method, '__call__'):
            methods.append(method)

    return methods


def get_plugin_methods(module_name, prefix):
    """
    Load methods from a given module
    Return the list on success
    Return None on error
    """
    try:
        module = __import__(module_name)
    except ImportError:
        log.error('Failed to import "{}"'.format(module_name))
        return None

    return get_methods(prefix, module)


def get_cli_methods():
    """
    Get built-in CLI methods
    """
    import blockstack_client.actions as builtin_methods
    all_methods = get_methods('cli_', builtin_methods)
    return all_methods


def prompt_args(arginfolist, prompt_func):
    """
    Prompt for args, using parsed method information
    Use prompt_func(help, name) to do the prompt
    Return a list of parsed arguments
    Return None on error
    """
    parsed_args = []
    for arg in arginfolist:
        name, help = arg['name'], arg['help']

        try:
            parsed_arg = None
            while True:
                try:
                    parsed_arg = prompt_func(help, name)
                    break
                except ValueError:
                    print('Invalid args. Please try again. {}:{}'.format(name, help), file=sys.stderr)
                    continue

            parsed_args.append(parsed_arg)
        except KeyboardInterrupt:
            print('Keyboard interrupt', file=sys.stderr)
            return None
        except Exception as e:
            log.exception(e)
            return None

    return parsed_args


def find_arg(argv, has_arg, short_opt, long_opt):
    """
    Find an option in an argument vector.
    If @has_arg is True, then the argument will be removed as well.
    Otherwise, the argument is assumed to be True

    Return (new argv, argument) on success.  The option and its argument will be removed.
    Return (None, None) if the option is present, but no argument is given and has_arg is True.
    If the option is not found, then argv will be unchanged, and None will be returned
    """
    arg = False
    if short_opt in argv or long_opt in argv:
        i = 1
        while i < len(argv):
            if argv[i] == short_opt or argv[i] == long_opt:
                if has_arg:
                    if i + 1 >= len(argv) or argv[i+1].startswith('-'):
                        # print('{}: missing argument'.format(argv[i], file=sys.stderr))
                        return (None, None)

                    arg = argv[i + 1]
                    argv.pop(i)
                    argv.pop(i)
                    # print('found {}/{} at {} ({})'.format(short_opt, long_opt, i, arg))
                    return (argv, arg)

                else:
                    argv.pop(i)
                    arg = True
                    # print('found {}/{} at {} ({})'.format(short_opt, long_opt, i, arg))

            else:
                i += 1

    return (argv, arg)


def parse_args(arg_defs, argv, config_path=CONFIG_PATH):
    """
    Given arg definitions, parse argv.
    Return {'status': True, 'new_argv': [...], 'args': {'argname': 'argvalue', ...}, 'envs': {'ENVAR': 'value', ...}, 're-exec': True/False}
    """
    ret = {}
    envs = {}
    re_exec = False
    for arg_name in arg_defs.keys():
        short_opt = arg_defs[arg_name]['short']
        long_opt = arg_defs[arg_name]['long']

        new_argv, arg_val = find_arg( argv, arg_defs[arg_name]['has_arg'], short_opt, long_opt )
        if new_argv is None:
            return {'error': 'Invalid argument {}/{}'.format(short_opt, long_opt)}

        ret[arg_name] = arg_val
        re_exec = re_exec or arg_defs[arg_name]['re-exec']

        if arg_defs[arg_name].has_key('env'):
            env_val = None
            if arg_val in (True, False) and arg_val:
                env_val = "1"
            else:
                env_val = arg_val

            if env_val:
                envs[ arg_defs[arg_name]['env'] ] = env_val

        argv = new_argv

    return {'status': True, 'new_argv': argv, 'args': ret, 'envs': envs, 're-exec': re_exec}


def run_cli(argv=None, config_path=CONFIG_PATH):
    """
    Run a CLI command from arguments (defaults to sys.argv)
    Return the result of the command on success.
    The result will be a dict, and will have 'error' defined on error condition.
    """

    if argv is None:
        argv = sys.argv

    global_cli_args = {
        'debug': {
            'short': '-d',
            'long': '--debug',
            'has_arg': False,
            're-exec': True,
            'env': 'BLOCKSTACK_DEBUG',
            'help': 'Enable global debugging messages'
        },
        'config': {
            'short': '-c',
            'long': '--config',
            'has_arg': True,
            're-exec': True,
            'env': 'BLOCKSTACK_CLIENT_CONFIG',
            'help': 'Path to alternative configuration file and associated state'
        },
        'default_yes': {
            'short': '-y',
            'long': '--yes',
            'has_arg': False,
            're-exec': False,
            'env': 'BLOCKSTACK_CLIENT_INTERACTIVE_YES',
            'help': 'Assume default/yes response to all queries',
        },
        'api_pass': {
            'short': '-a',
            'long': '--api_password',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_API_PASSWORD',
            'help': 'API password to use',
        },
        'api_session': {
            'short': '-A',
            'long': '--api_session',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_API_SESSION',
            'help': 'API session token to use',
        },
        'api_bind': {
            'short': '-b',
            'long': '--bind',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_API_BIND',
            'help': 'Address or hostname to bind the API server',
        },
        'dry_run': {
            'short': '-n',
            'long': '--dry_run',
            'has_arg': False,
            're-exec': True,
            'env': 'BLOCKSTACK_DRY_RUN',
            'help': 'Do not send transactions. Return the signed transaction instead.'
        },
        'wallet_password': {
            'short': '-p',
            'long': '--password',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_CLIENT_WALLET_PASSWORD',
            'help': 'Wallet decryption password',
        },
        'indexer_host': {
            'short': '-H',
            'long': '--host',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_CLI_SERVER_HOST',
            'help': 'Hostname or IP address of the Blockstack blockchain indexer',
        },
        'indexer_port': {
            'short': '-P',
            'long': '--port',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_CLI_SERVER_PORT',
            'help': 'Port number of the Blockstack blockchain indexer',
        },
    }

    if '-v' in argv or '--version' in argv:
        print(VERSION)
        sys.exit(0)

    arg_info = parse_args( global_cli_args, argv, config_path=config_path )
    if 'error' in arg_info:
        print("Failed to parse global CLI arguments: {}".format(arg_info['error']), file=sys.stderr)
        print("Global CLI arguments:\n{}\n".format( "\n".join( ["\t{}/{}\n\t\t{}".format(cliarg['short'], cliarg['long'], cliarg['help']) for cliarg in global_cli_args] )), file=sys.stderr)
        sys.exit(1)

    cli_debug = arg_info['args']['debug']
    cli_config_argv = (arg_info['args'].has_key('config'))

    # set environment variables
    for envar, enval in arg_info['envs'].items():
        if os.environ.get(envar) is None:
            if cli_debug:
                print("Set {} to {}".format(envar, enval), file=sys.stderr)

            os.environ[envar] = enval
    
    # re-exec?
    if arg_info['re-exec']:
        if cli_debug:
            new_argv = arg_info['new_argv']
            print("Re-exec as `{}`".format( " ".join(new_argv)), file=sys.stderr)

            os.execv( new_argv[0], new_argv )
    
    # do one-time opt-in request
    uuid_path = client_uuid_path(config_dir=os.path.dirname(config_path))
    first_time = False
    client_uuid = None
    
    if not os.path.exists(uuid_path):
        first_time = True
        client_uuid = get_or_set_uuid(config_dir=os.path.dirname(config_path))

        if os.environ.get('BLOCKSTACK_CLIENT_INTERACTIVE_YES') != '1':
            # interactive allowed
            # prompt for email 
            print("Would you like to receive an email when there is a new release of this software available?")
            email_addr = raw_input("Email address (leave blank to opt out): ")

            # will only process real email addresses when we email announcements out
            if len(email_addr) > 0:
                analytics_user_register( client_uuid, email_addr )

    conf = config.get_config(path=config_path, interactive=(os.environ.get('BLOCKSTACK_CLIENT_INTERACTIVE_YES') != '1'))
    if conf is None:
        return {'error': 'Failed to load config'}

    conf_version = conf.get('client_version', '')
    if not semver_match(conf_version, VERSION):
        # back up the config file 
        if not cli_config_argv:
            # default config file
            backup_path = config.backup_config_file(config_path=config_path)
            if not backup_path:
                exit_with_error("Failed to back up legacy configuration file {}".format(config_path))

            else:
                exit_with_error("Backed up legacy configuration file from {} to {} and re-generated a new, default configuration.  Please restart.".format(config_path, backup_path))

    advanced_mode = conf.get('advanced_mode', False)

    parser = argparse.ArgumentParser(
        description='Blockstack cli version {}'.format(config.VERSION)
    )

    all_methods = []
    subparsers = parser.add_subparsers(dest='action')

    # add basic methods
    all_method_names = get_cli_methods()
    all_methods = parse_methods(all_method_names)
    build_method_subparsers(subparsers, all_methods)

    if not advanced_mode:
        # remove advanced methods 
        all_methods = filter( lambda m: 'advanced' not in m['pragmas'], all_methods ) 

    # Print default help message, if no argument is given
    if len(argv) == 1 or '-h' in argv or '--help' in argv:
        parser.print_help()
        sys.exit(0)

    interactive, args, directive = False, None, None

    try:
        args, unknown_args = parser.parse_known_args(args=argv[1:])
        directive = args.action
    except SystemExit:
        # bad arguments
        # special case: if the method is specified, but no method arguments are given,
        # then switch to prompting the user for individual arguments.
        try:
            directive_parser = argparse.ArgumentParser(
                description='Blockstack cli version {}'.format(config.VERSION)
            )
            directive_subparsers = directive_parser.add_subparsers(
                dest='action'
            )

            # only parse the directive
            build_method_subparsers(
                directive_subparsers, all_methods, include_args=False, include_opts=False
            )
            directive_args, directive_unknown_args = directive_parser.parse_known_args(
                args=argv[1:]
            )

            # want interactive prompting
            interactive, directive = True, directive_args.action

        except SystemExit:
            # still invalid
            parser.print_help()
            return {'error': 'Invalid arguments.  Try passing "-h".'}

    result = {}

    blockstack_server, blockstack_port = conf['server'], conf['port']

    # initialize blockstack connection
    session(
        conf=conf, server_host=blockstack_server,
        server_port=blockstack_port, set_global=True
    )

    prompt_func = lambda help, name: raw_input('optional: {} ("{}"): '.format(help, name))

    # dispatch to the apporpriate method
    for method_info in all_methods:
        if directive != method_info['command']:
            continue

        method = method_info['method']
        pragmas = method_info['pragmas']

        # interactive?
        if interactive:
            print('')
            print('Interactive prompt engaged.  Press Ctrl+C to quit')
            print('Help for "{}": {}'.format(method_info['command'], method_info['help']))
            print('')

            required_args = prompt_args(method_info['args'], prompt_func)
            if required_args is None:
                return {'error': 'Failed to prompt for arguments'}

            optional_args = prompt_args(method_info['opts'], prompt_func)
            if optional_args is None:
                return {'error': 'Failed to prompt for arguments'}

            full_args = [method_info['command']] + required_args + optional_args
            try:
                args, unknown_args = parser.parse_known_args(args=full_args)
            except SystemExit:
                # invalid arguments
                return {'error': 'Invalid arguments.  Please try again.'}

        result = method(args, config_path=config_path)
        return {'status': True, 'result': result, 'pragmas': pragmas}

    # not found
    return {'error': 'No such command "{}"'.format(args.action)}


if __name__ == '__main__':
    result = run_cli()
    if 'error' in result:
        exit_with_error(result['error'])
    else:
        if 'raw' in result['pragmas']:
            print(result['result'])

        else:
            print_result(result['result'])

        sys.exit(0)
