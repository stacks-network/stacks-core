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
from blockstack_client.client import session
from blockstack_client.config import CONFIG_PATH, VERSION, semver_match
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
                    print('Invalid args. Please try again. {}:{}'.format(name, help))
                    continue

            parsed_args.append(parsed_arg)
        except KeyboardInterrupt:
            print('Keyboard interrupt')
            return None
        except Exception as e:
            log.exception(e)
            return None

    return parsed_args


def run_cli(argv=None, config_path=CONFIG_PATH):
    """
    Run a CLI command from arguments (defaults to sys.argv)
    Return the result of the command on success.
    The result will be a dict, and will have 'error' defined on error condition.
    """

    if argv is None:
        argv = sys.argv

    # alternative config path?
    if '-c' in argv or '--config' in argv:
        i = 1
        while i < len(argv):
            if argv[i] == '-c' or argv[i] == '--config':
                if i + 1 >= len(argv):
                    print('{}: missing path'.format(argv[i]), file=sys.stderr)
                    sys.exit(1)

                config_path = argv[i + 1]
                argv.pop(i)
                argv.pop(i)

            else:
                i += 1

    log.debug('Use config file {}'.format(config_path))

    conf = config.get_config(path=config_path)
    if conf is None:
        return {'error': 'Failed to load config'}

    conf_version = conf.get('client_version', '')
    if not semver_match(conf_version, VERSION):
        message = (
            'Your configuration file ({}) is out of date. Please move it and ',
            'try again in order to automatically generate a new config file.'
        )
        exit_with_error(
            'Invalid configuration file: {} != {}'.format(conf_version, VERSION),
            message.format(config_path)
        )

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
    if len(argv) == 1:
        parser.print_help()
        return {}

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
        return result

    # not found
    return {'error': 'No such command "{}"'.format(args.action)}


if __name__ == '__main__':
    result = run_cli()
    if 'error' in result:
        exit_with_error(result['error'])
    else:
        print_result(result)
        sys.exit(0)
