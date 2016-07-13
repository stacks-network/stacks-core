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

import config
import argparse
import re

def parse_methods( method_list ):
    """
    Given a list of methods, parse their docstring metadata for linking information.
    The __doc__ string for each method must be properly formatted:

    command: <command name>
        This is the name of the CLI command

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
    }

    Raise an exception if we fail to parse any method.
    """
    
    ret = []
    for method in method_list:
        docstr = method.__doc__
        doclines = filter( lambda l: len(l.strip()) > 0, docstr.split("\n") )
        doclines = [l.strip() for l in doclines]

        # first line: command name 
        command_line = doclines[0]
        if not command_line.startswith("command:"):
            raise ValueError("Method %s: invalid command string '%s'" % (method.__name__, command_line))

        # first line must be 'help:'
        help_line = doclines[1]
        if not help_line.startswith("help:"):
            raise ValueError("Method %s: invalid help string '%s'" % (method.__name__, help_line))

        arg_lines = doclines[2:]
        # following lines must be 'arg:' or 'opt:'
        for l in arg_lines:
            if not l.startswith("arg:") and not l.startswith("opt:"):
                raise ValueError("Method %s: invalid arg string '%s'" % (method.__name__, l))

        # parse command and help
        try:
            command = re.findall( "^command:[ \t]+([^ \t]+)$", command_line )[0]
            command_help = re.findall( "^help:[ \t]+(.+)$", help_line )[0]
        except:
            raise ValueError("Method %s: invalid command and/or help string" % (method.__name__))

        args = []
        opts = []

        # parse args 
        for l in arg_lines:
            arg_parts = None
            required = False

            if l.startswith("arg:"):
                arg_parts = re.findall( '^arg:[ \t]+([^ \t]+)[ \t]+\((.+)\)[ \t]+"([^"]+)"$', l )
                required = True
            
            elif l.startswith("opt:"):
                arg_parts = re.findall( '^opt:[ \t]+([^ \t]+)[ \t]+\((.+)\)[ \t]+"([^"]+)"$', l )
                required = False 

            try:
                assert len(arg_parts) == 1
                arg_name, arg_type, arg_help = arg_parts[0]
                assert arg_type in ['str', 'int']
                arg_type = eval(arg_type)
                
            except:
                raise ValueError("Method %s: Failed to parse arg string '%s'" % (method.__name__, l))

            if required:
                args.append( {'name': arg_name, 'type': arg_type, 'help': arg_help} )
            else:
                opts.append( {'name': arg_name, 'type': arg_type, 'help': arg_help} )
   
        ret.append({
            'method': method,
            'command': command,
            'help': command_help,
            'args': args,
            'opts': opts
        })

    return ret


def build_method_subparsers( subparsers, method_infos, include_args=True, include_opts=True ):
    """
    Using parsed method information from parse_methods,
    populate a parser with subparsers for the method's command,
    args/opts, and help.

    Return True on success.
    """
    for method_info in method_infos:
        subparser = subparsers.add_parser( method_info['command'], help=method_info['help'] )

        if include_args:
            for arg in method_info['args']:
                subparser.add_argument( arg['name'], type=arg['type'], help=arg['help'] )

        if include_opts:
            for opt in method_info['opts']:
                subparser.add_argument( opt['name'], type=opt['type'], nargs='?', help=opt['help'] )

    return True


