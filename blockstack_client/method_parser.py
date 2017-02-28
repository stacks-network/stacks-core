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

import re

import config

log = config.get_logger('blockstack-client')


def parse_methods(method_list):
    """
    Given a list of methods, parse their docstring metadata for linking information.
    The __doc__ string for each method must be properly formatted:

    command: <command name> [rpc] [advanced] 
        This is the name of the CLI command
        If rpc is present, the command will be accessible via RPC.
        If advanced is present, then the command will be accessible only in advanced mode

    help: <help string>
        This is the help string for the command

    arg: <argname> (<argtype>) "<arghelp>"
        This is a required argument, with <argname> as a name and <argtype> as a type, with help string <arghelp>

    opt: <argname> (<argtype>) "<arghelp>"
        This is an optional argument, with <argname> as a name and <argtype> as a type, with help string <arghelp>

    Returns a list of dicts of
    {
        'command': command
        'help': help
        'args': [{'name': name, 'type': type, 'help': help}]
        'opts': [{'name': name, 'type': type, 'help': help}]
        'method': method
        'pragmas': ['pragma', 'pragma', ...]
    }

    Raise an exception if we fail to parse any method.
    """

    ret = []

    command_pattern = re.compile(r'^command:[ \t]+([^ \t]+)[ ]*(.*)[ ]*$')
    help_pattern = re.compile(r'^help:[ \t]+(.+)$')

    # NOTE: pattern must be defined using double-quotes
    arg_opt_pattern = r"^{}[ \t]+([^ \t]+)[ \t]+\((.+)\)[ \t]+'([^']+)'$"
    arg_pattern = re.compile(arg_opt_pattern.format('arg:'))
    opt_pattern = re.compile(arg_opt_pattern.format('opt:'))

    error_msg = 'Method {}: {} string "{}"'

    supported_pragmas = ['', 'rpc', 'advanced', 'check_storage', 'raw']

    for method in method_list:
        method_name = method.__name__
        docstr = method.__doc__
        doclines = [l.strip() for l in docstr.split('\n') if l.strip()]

        # first line: command name
        command_line = doclines[0]
        if not command_line.startswith('command:'):
            raise ValueError(error_msg.format(method_name, 'invalid command', command_line))

        # first line must be 'help:'
        help_line = doclines[1]
        if not help_line.startswith('help:'):
            raise ValueError(error_msg.format(method_name, 'invalid help', command_line))

        arg_lines = doclines[2:]
        # following lines must be 'arg:' or 'opt:'
        for l in arg_lines:
            if not l.startswith('arg:') and not l.startswith('opt:'):
                raise ValueError(error_msg.format(method_name, 'invalid arg', command_line))

        # parse command and help
        try:
            command_parts = re.findall(command_pattern, command_line)[0]
            command = command_parts[0]
            command_pragmas = command_parts[1].split(' ')

            unsupported_pragmas = list(set(command_pragmas) - set(supported_pragmas))
            if unsupported_pragmas:
                log.error('Unsupported pragmas: {}'.format(unsupported_pragmas))
                raise ValueError("Unsupported pragmas: {}".format(unsupported_pragmas))

            command_help = re.findall(help_pattern, help_line)[0]
        except Exception as e:
            log.exception(e)
            raise ValueError(error_msg.format(method_name, 'invalid command and/or help', ''))

        args, opts = [], []

        # parse args
        for l in arg_lines:
            arg_parts, required = None, False

            if l.startswith('arg:'):
                arg_parts = re.findall(arg_pattern, l)
                required = True
            elif l.startswith('opt:'):
                arg_parts = re.findall(opt_pattern, l)
                required = False

            try:
                assert len(arg_parts) == 1, "len(arg_parts) = {}".format(len(arg_parts))
                arg_name, arg_type, arg_help = arg_parts[0]
                assert arg_type in ['str', 'int'], "arg_type is {}".format(arg_type)
                arg_type = eval(arg_type)
            except AssertionError as ae:
                if config.BLOCKSTACK_DEBUG:
                    log.exception(ae)

                raise ValueError(error_msg.format(method_name, 'failed to parse arg', l))

            name_type = {'name': arg_name, 'type': arg_type, 'help': arg_help}
            if required:
                args.append(name_type)
            else:
                opts.append(name_type)

        ret.append({
            'method': method,
            'command': command,
            'help': command_help,
            'args': args,
            'opts': opts,
            'pragmas': command_pragmas
        })

    return ret


def build_method_subparsers(subparsers, method_infos, include_args=True, include_opts=True):
    """
    Using parsed method information from parse_methods,
    populate a parser with subparsers for the method's command,
    args/opts, and help.

    Return True on success.
    """
    for method_info in method_infos:
        subparser = subparsers.add_parser(method_info['command'], help=method_info['help'])

        if include_args:
            for arg in method_info['args']:
                subparser.add_argument(arg['name'], type=arg['type'], help=arg['help'])

        if include_opts:
            for opt in method_info['opts']:
                subparser.add_argument(opt['name'], type=opt['type'], nargs='?', help=opt['help'])

    return True
