#!/usr/bin/env python2
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
import sys, os
import requests
import traceback
requests.packages.urllib3.disable_warnings()

import logging
logging.disable(logging.CRITICAL)

from blockstack_client import config
from blockstack_client.client import session
from blockstack_client.constants import WALLET_FILENAME, set_secret, serialize_secrets, write_secrets, load_secrets, CONFIG_PATH
from blockstack_client.config import CONFIG_PATH, VERSION, client_uuid_path, get_or_set_uuid
from blockstack_client.method_parser import parse_methods, build_method_subparsers

from .wallet import inspect_wallet
from utils import exit_with_error, print_result

log = config.get_logger()

# a less-verbose argument parser
class BlockstackArgumentParser(argparse.ArgumentParser):
    def print_usage(self, *args, **kw):
        pass

    def exit(self, *args, **kw):
        raise SystemExit()


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
    Return {'status': True, 'new_argv': [...], 'args': {'argname': 'argvalue', ...}, 'envs': {'ENVAR': 'value', ...}, 'secrets': {'SECRET': 'value', ...}, 're-exec': True/False}
    """
    ret = {}
    envs = {}
    secrets = {}
    re_exec = False

    for arg_name in arg_defs.keys():
        similars = arg_defs[arg_name]['similar']
        for similar in similars:
            if similar in argv:
                return {'error': 'Invalid argument {}'.format(similar), 'similar': {"{}/{}".format(arg_defs[arg_name]['short'], arg_defs[arg_name]['long']): similar}}

    for arg_name in arg_defs.keys():
        short_opt = arg_defs[arg_name]['short']
        long_opt = arg_defs[arg_name]['long']
        
        new_argv, arg_val = find_arg( argv, arg_defs[arg_name]['has_arg'], short_opt, long_opt)
        if new_argv is None:
            # catch similar-sounding (but wrong) arguments
            error = {'error': 'Invalid argument {}/{}'.format(short_opt, long_opt)}
            return error

        ret[arg_name] = arg_val

        if not arg_val:
            # not found
            continue

        re_exec = re_exec or arg_defs[arg_name]['re-exec']

        if arg_defs[arg_name].has_key('env'):
            env_val = None
            if arg_val in (True, False) and arg_val:
                env_val = "1"
            else:
                env_val = arg_val

            if env_val:
                if arg_defs[arg_name].get('secret'):
                    secrets[ arg_defs[arg_name]['env'] ] = env_val
                
                else:
                    envs[ arg_defs[arg_name]['env'] ] = env_val

        argv = new_argv

    return {'status': True, 'new_argv': argv, 'args': ret, 'envs': envs, 'secrets': secrets, 're-exec': re_exec}


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
            'help': 'Enable global debugging messages',
            'similar': ['--dbg', '-dd', '-ddd', '-dddd', '--verbose'],
            'secret': False,
        },
        'config': {
            'short': '-c',
            'long': '--config',
            'has_arg': True,
            're-exec': True,
            'env': 'BLOCKSTACK_CLIENT_CONFIG',
            'help': 'Path to alternative configuration file and associated state',
            'similar': ['--conf'],
            'secret': False,
        },
        'default_yes': {
            'short': '-y',
            'long': '--yes',
            'has_arg': False,
            're-exec': False,
            'env': 'BLOCKSTACK_CLIENT_INTERACTIVE_YES',
            'help': 'Assume default/yes response to all queries',
            'similar': [],
            'secret': False,
        },
        'api_pass': {
            'short': '-a',
            'long': '--api_password',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_API_PASSWORD',
            'help': 'API password to use',
            'similar': ['--api-password', '--api-pass', '--api_pass'],
            'secret': True,
        },
        'api_session': {
            'short': '-A',
            'long': '--api_session',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_API_SESSION',
            'help': 'API session token to use',
            'similar': ['--api-session', '--session', '--ses'],
            'secret': True,
        },
        'api_bind': {
            'short': '-b',
            'long': '--bind',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_API_BIND',
            'help': 'Address or hostname to bind the API server',
            'similar': [],
            'secret': False,
        },
        'dry_run': {
            'short': '-n',
            'long': '--dry_run',
            'has_arg': False,
            're-exec': True,
            'env': 'BLOCKSTACK_DRY_RUN',
            'help': 'Do not send transactions. Return the signed transaction instead.',
            'similar': ['--dry-run', '--dryrun'],
            'secret': False,
        },
        'wallet_password': {
            'short': '-p',
            'long': '--password',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_CLIENT_WALLET_PASSWORD',
            'help': 'Wallet decryption password',
            'similar': ['--pass', '--passwd'],
            'secret': True,
        },
        'indexer_host': {
            'short': '-H',
            'long': '--host',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_CLI_SERVER_HOST',
            'help': 'Hostname or IP address of the Blockstack blockchain indexer',
            'similar': ['--ip', '--ipv4'],
            'secret': False,
        },
        'indexer_port': {
            'short': '-P',
            'long': '--port',
            'has_arg': True,
            're-exec': False,
            'env': 'BLOCKSTACK_CLI_SERVER_PORT',
            'help': 'Port number of the Blockstack blockchain indexer',
            'similar': [],
            'secret': False,
        },
        'secret_fd': {
            'short': '-f',
            'long': '--secrets',
            'has_arg': True,
            're-exec': False,
            'help': 'Used internally; file descriptor number to serialized secrets preserved across execv(2).',
            'similar': [],
            'secret': False,
        },
    }

    if '-v' in argv or '--version' in argv:
        print(VERSION)
        sys.exit(0)

    arg_info = parse_args( global_cli_args, argv, config_path=config_path )
    if 'error' in arg_info:
        print("Failed to parse global CLI arguments: {}".format(arg_info['error']), file=sys.stderr)
        print("Global CLI arguments:\n{}\n".format( "\n".join( ["\t{}/{}\n\t\t{}".format(cliarg['short'], cliarg['long'], cliarg['help']) for argname, cliarg in global_cli_args.items()] )), file=sys.stderr)

        if 'similar' in arg_info:
            siminfo = arg_info['similar']
            assert len(siminfo.keys()) == 1
            opt = siminfo.keys()[0]
            arg = siminfo[opt]

            print("Suggestion:  Use '{}' instead of '{}'".format(opt, arg), file=sys.stderr)

        sys.exit(1)

    cli_debug = arg_info['args'].get('debug')
    cli_config_argv = (arg_info['args'].has_key('config'))

    # set (non-secret) environment variables
    for envar, enval in arg_info['envs'].items():
        if os.environ.get(envar) is None:
            if cli_debug:
                print("Set {} to {}".format(envar, enval), file=sys.stderr)

            os.environ[envar] = enval

    # set secrets...
    for secvar, secval in arg_info['secrets'].items():
        set_secret(secvar, secval)

    # re-exec?
    if arg_info['re-exec']:
 
        new_argv = arg_info['new_argv']

        if len(arg_info['secrets']) > 0:
            secbuf = serialize_secrets()
            fd = write_secrets(secbuf)

            new_argv += ['--secrets', str(fd)]

        new_argv = [sys.executable] + new_argv
        if cli_debug:
            print("Re-exec as `{}`".format(", ".join([
                '"{}"'.format(i) for i in new_argv])), file=sys.stderr)

        try:
            os.execv(new_argv[0], new_argv)
        except:
            import traceback as tb
            tb.print_exc()
            sys.exit(1)

    # load secrets
    if arg_info['args'].has_key('secret_fd'):
        fd_str = arg_info['args']['secret_fd']
        if fd_str:
            try:
                fd = int(fd_str)
            except:
                print('Invalid secret fd {}'.format(fd_str), file=sys.stderr)
                sys.exit(1)

            log.debug("Load secrets from {}".format(fd))

            try:
                os.lseek(fd, 0, os.SEEK_SET)
                secbuf = os.read(fd, 65536)
                os.close(fd)

                load_secrets(secbuf)
            except Exception as e:
                traceback.print_exc()
                sys.exit(1)

    # do one-time opt-in request
    uuid_path = client_uuid_path(config_dir=os.path.dirname(config_path))
    first_time = False
    client_uuid = None
    
    if not os.path.exists(uuid_path):
        first_time = True
        client_uuid = get_or_set_uuid(config_dir=os.path.dirname(config_path))

    res = config.setup_config(config_path=config_path, interactive=(os.environ.get("BLOCKSTACK_CLIENT_INTERACTIVE_YES") != '1'))
    if 'error' in res:
        exit_with_error("Failed to load and verify config file: {}".format(res['error']))
   
    conf = res['config']

    # if the wallet exists, make sure that it's the latest version 
    wallet_path = os.path.join(os.path.dirname(config_path), WALLET_FILENAME)
    if os.path.exists(wallet_path):
        res = inspect_wallet(wallet_path=wallet_path)
        if 'error' in res:
            exit_with_error("Failed to inspect wallet at {}".format(wallet_path))

        if res['migrate'] or res['format'] != 'current':
            if len(sys.argv) <= 1 or sys.argv[1] != 'setup_wallet':
                exit_with_error("Wallet is in legacy format.  Please unlock and migrate it with `blockstack setup_wallet`.")

    parser = BlockstackArgumentParser(
        description='Blockstack cli version {}'.format(config.VERSION)
    )

    all_methods = []
    subparsers = parser.add_subparsers(dest='action')

    # add basic methods
    all_method_names = get_cli_methods()
    all_methods = parse_methods(all_method_names)
    build_method_subparsers(subparsers, all_methods)

    # Print default help message, if no argument is given
    if len(argv) == 1 or '-h' in argv or '--help' in argv:
        parser.print_help()
        sys.exit(0)

    interactive, args, directive = False, None, None

    try:
        # capture stderr so we don't repeat ourselves
        args, unknown_args = parser.parse_known_args(args=argv[1:])
        directive = args.action
    except SystemExit:
        # bad arguments
        # special case: if the method is specified, but no method arguments are given,
        # then switch to prompting the user for individual arguments.
        try:
            directive_parser = BlockstackArgumentParser(
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
            return {'error': 'Invalid arguments.  Try passing "-h".'}

    result = {}

    blockstack_server, blockstack_port = conf['blockstack-client']['server'], conf['blockstack-client']['port']

    # initialize blockstack connection
    session(
        server_host=blockstack_server,
        server_port=blockstack_port, set_global=True
    )

    prompt_func_arg = lambda help, name: raw_input('required: {} ("{}"): '.format(help, name))
    prompt_func_opt = lambda help, name: raw_input('optional: {} ("{}"): '.format(help, name))

    # dispatch to the apporpriate method
    for method_info in all_methods:
        if directive != method_info['command']:
            continue

        method = method_info['method']
        pragmas = method_info['pragmas']

        # interactive?
        if interactive:
            arg_names = [mi['name'] for mi in method_info['args']]
            opt_names = [mi['name'] for mi in method_info['opts']]
            arg_usage = ' '.join(arg_names)
            opt_usage = ' '.join( ['[{}]'.format(opt) for opt in opt_names] )

            print('')
            print('Interactive prompt engaged.  Press Ctrl+C to quit')
            print('Help for "{}": {}'.format(method_info['command'], method_info['help']))
            print('Arguments: {} {} {}'.format(method_info['command'], arg_usage, opt_usage))
            print('')

            required_args = prompt_args(method_info['args'], prompt_func_arg)
            if required_args is None:
                return {'error': 'Failed to prompt for arguments'}

            optional_args = prompt_args(method_info['opts'], prompt_func_opt)
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
