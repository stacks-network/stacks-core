#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function

"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2014 by Halfmoon Labs, Inc.
    copyright: (c) 2015 by Blockstack.org

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

import os
import sys
import itertools
import logging
import traceback
import uuid
import urllib2
import copy
import time
import shutil
import requests
import keylib
import json

from binascii import hexlify
from ConfigParser import SafeConfigParser

import virtualchain
from .utxo import (
    SUPPORTED_UTXO_PROVIDERS, default_utxo_provider_opts,
    SUPPORTED_UTXO_PARAMS, SUPPORTED_UTXO_PROMPT_MESSAGES,
    connect_utxo_provider
)
from .constants import (
    NAME_REGISTRATION, OPCODE_NAMES, CONFIG_DIR, CONFIG_PATH,
    TX_MIN_CONFIRMATIONS, BLOCKSTACKD_SERVER, BLOCKSTACKD_PORT,
    METADATA_DIRNAME, BLOCKSTACK_DEFAULT_STORAGE_DRIVERS,
    BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE, DEFAULT_API_PORT,
    DEFAULT_API_HOST, DEFAULT_QUEUE_PATH, DEFAULT_POLL_INTERVAL,
    DEFAULT_BLOCKCHAIN_READER, DEFAULT_BLOCKCHAIN_WRITER,
    VERSION
)
from .logger import get_logger

log = get_logger('blockstack-client')


# NOTE: duplicated from blockstack-core and streamlined.
def op_get_opcode_name(op_string):
    """
    Get the name of an opcode, given the 'op' byte sequence of the operation.
    """
    global OPCODE_NAMES

    # special case...
    if op_string == '{}:'.format(NAME_REGISTRATION):
        return 'NAME_RENEWAL'

    op = op_string[0]
    if op not in OPCODE_NAMES:
        raise Exception('No such operation "{}"'.format(op))

    return OPCODE_NAMES[op]


def interactive_prompt(message, parameters, default_opts):
    """
    Prompt the user for a series of parameters
    Return a dict mapping the parameter name to the
    user-given value.
    """

    # pretty-print the message
    lines = message.split('\n')
    max_line_len = max([len(l) for l in lines])

    print('-' * max_line_len)
    print(message)
    print('-' * max_line_len)

    ret = {}
    for param in parameters:
        formatted_param = param
        prompt_str = '{}: '.format(formatted_param)
        if param in default_opts:
            prompt_str = '{} (default: "{}"): '.format(formatted_param, default_opts[param])

        try:
            value = raw_input(prompt_str)
        except KeyboardInterrupt:
            log.debug('Exiting on keyboard interrupt')
            sys.exit(0)

        if len(value) > 0:
            ret[param] = value
        elif param in default_opts:
            ret[param] = default_opts[param]
        else:
            ret[param] = None

    return ret


def find_missing(message, all_params, given_opts, default_opts, header=None, prompt_missing=True):
    """
    Find and interactively prompt the user for missing parameters,
    given the list of all valid parameters and a dict of known options.

    Return the (updated dict of known options, missing, num_prompted), with the user's input.
    """

    # are we missing anything?
    missing_params = list(set(all_params) - set(given_opts))

    num_prompted = 0

    if not missing_params:
        return given_opts, missing_params, num_prompted

    if not prompt_missing:
        # count the number missing, and go with defaults
        missing_values = set(default_opts) - set(given_opts)
        num_prompted = len(missing_values)
        given_opts.update(default_opts)

    else:
        if header is not None:
            print('-' * len(header))
            print(header)

        missing_values = interactive_prompt(message, missing_params, default_opts)
        num_prompted = len(missing_values)
        given_opts.update(missing_values)

    return given_opts, missing_params, num_prompted


def opt_strip(prefix, opts):
    """
    Given a dict of opts that start with prefix,
    remove the prefix from each of them.
    """

    ret = {}
    for opt_name, opt_value in opts.items():
        # remove prefix
        if opt_name.startswith(prefix):
            opt_name = opt_name[len(prefix):]

        ret[opt_name] = opt_value

    return ret


def opt_restore(prefix, opts):
    """
    Given a dict of opts, add the given prefix to each key
    """

    return {prefix + name: value for name, value in opts.items()}


def default_bitcoind_opts(config_file=None, prefix=False):
    """
    Get our default bitcoind options, such as from a config file,
    or from sane defaults
    """

    default_bitcoin_opts = virtualchain.get_bitcoind_config(config_file=config_file)

    # drop dict values that are None
    default_bitcoin_opts = {k: v for k, v in default_bitcoin_opts.items() if v is not None}

    # strip 'bitcoind_'
    if not prefix:
        default_bitcoin_opts = opt_strip('bitcoind_', default_bitcoin_opts)

    return default_bitcoin_opts


def client_uuid_path(config_dir=CONFIG_DIR):
    """
    where is the client UUID stored
    """
    uuid_path = os.path.join(config_dir, 'client.uuid')
    return uuid_path


def device_id_path(config_dir=CONFIG_DIR):
    """
    get device ID path
    """
    id_path = os.path.join(config_dir, 'client.device_id')
    return id_path


def get_or_set_uuid(config_dir=CONFIG_DIR):
    """
    Get or set the UUID for this installation.
    Return the UUID either way
    Return None on failure
    """
    uuid_path = client_uuid_path(config_dir=config_dir)
    u = None
    if os.path.exists(uuid_path):
        try:
            with open(uuid_path, 'r') as f:
                u = f.read()
                u = u.strip()
        except Exception as e:
            log.exception(e)
            return None
    else:
        try:
            u = str(uuid.uuid4())
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)

            with open(uuid_path, 'w') as f:
                f.write(u)
                f.flush()
                os.fsync(f.fileno())

        except Exception as e:
            log.exception(e)
            return None

    return u


def get_local_device_id(config_dir=CONFIG_DIR):
    """
    Get the local device ID
    """
    id_path = device_id_path(config_dir=config_dir)
    did = None
    if os.path.exists(id_path):
        try:
            with open(id_path, 'r') as f:
                did = f.read()

            return did
        except Exception as e:
            log.exception(e)
    
    return get_or_set_uuid(config_dir=config_dir)



def configure(config_file=CONFIG_PATH, force=False, interactive=True, set_migrate=False):
    """
    Configure blockstack-client:  find and store configuration parameters to the config file.

    Optionally prompt for missing data interactively (with interactive=True).  Or, raise an exception
    if there are any fields missing.

    Optionally force a re-prompting for all configuration details (with force=True)

    Return {
       'blockstack-client': { ... },
       'bitcoind': { ... },
       'blockchain-reader': { ... },
       'blockchain-writer': { ... },
       'uuid': ...
    }
    """

    if not os.path.exists(config_file) and interactive:
        # definitely ask for everything
        force = True

    config_dir = os.path.dirname(config_file)

    # get blockstack client opts
    blockstack_message = (
        'Your client does not have enough information to connect\n'
        'to a Blockstack server.  Please supply the following\n'
        'parameters, or press [ENTER] to select the default value.'
    )

    all_opts = read_config_file(config_path=config_file, set_migrate=set_migrate)
    blockstack_opts = {}
    blockstack_opts_defaults = all_opts['blockstack-client']

    migrated = False
    if set_migrate:
        migrated = all_opts['migrated']
        del all_opts['migrated']

    blockstack_params = blockstack_opts_defaults.keys()

    if not force:
        # defaults
        blockstack_opts = copy.deepcopy(blockstack_opts_defaults)

    blockstack_opts, missing_blockstack_opts, num_blockstack_opts_prompted = find_missing(
        blockstack_message,
        blockstack_params,
        blockstack_opts,
        blockstack_opts_defaults,
        prompt_missing=interactive
    )

    subdomain_opts_defaults = all_opts['subdomain-resolution']
    subdomain_opts, missing_subdomain_opts, _ = find_missing(
        "Configuring faster subdomain resolution.",
        subdomain_opts_defaults.keys(),
        subdomain_opts_defaults,
        subdomain_opts_defaults,
        prompt_missing=interactive
    )

    # get bitcoind options
    bitcoind_message = (
        'Blockstack does not have enough information to connect\n'
        'to bitcoind.  Please supply the following parameters, or\n'
        'press [ENTER] to select the default value.'
    )

    bitcoind_opts = {}
    bitcoind_opts_defaults = default_bitcoind_opts(config_file=config_file)
    bitcoind_opts_defaults.update(all_opts.get('bitcoind', {}))
    bitcoind_params = bitcoind_opts_defaults.keys()

    if not force:
        # get default set of bitcoind opts
        bitcoind_opts = copy.deepcopy(bitcoind_opts_defaults)

    # get any missing bitcoind fields
    bitcoind_opts, missing_bitcoin_opts, num_bitcoind_prompted = find_missing(
        bitcoind_message,
        bitcoind_params,
        bitcoind_opts,
        bitcoind_opts_defaults,
        prompt_missing=interactive
    )

    # find the blockchain reader
    blockchain_reader = blockstack_opts.get('blockchain_reader')
    while blockchain_reader not in SUPPORTED_UTXO_PROVIDERS:
        if not(interactive or force):
            raise Exception('No blockchain reader given')

        # prompt for it?
        blockchain_message = (
            'NOTE: Blockstack currently requires an external API\n'
            'for querying the blockchain.  The set of supported\n'
            'service providers are:\n'
            '\t\n'.join(SUPPORTED_UTXO_PROVIDERS) + '\n'
            'Please enter the requisite information here.'
        )

        blockchain_reader_dict = interactive_prompt(blockchain_message, ['blockchain_reader'], {})
        blockchain_reader = blockchain_reader_dict['blockchain_reader']

    blockchain_reader_defaults = default_utxo_provider_opts(blockchain_reader, config_file=config_file)
    blockchain_reader_defaults.update(all_opts.get('blockchain_reader', {}))
    blockchain_reader_params = SUPPORTED_UTXO_PARAMS[blockchain_reader]

    # get current set of reader opts
    blockchain_reader_opts = {} if force else copy.deepcopy(blockchain_reader_defaults)

    blockchain_reader_opts, missing_reader_opts, num_reader_opts_prompted = find_missing(
        SUPPORTED_UTXO_PROMPT_MESSAGES[blockchain_reader],
        blockchain_reader_params,
        blockchain_reader_opts,
        blockchain_reader_defaults,
        header='Blockchain reader configuration',
        prompt_missing=interactive
    )

    blockchain_reader_opts['utxo_provider'] = blockchain_reader_defaults['utxo_provider']

    # find the blockchain writer
    blockchain_writer = blockstack_opts.get('blockchain_writer')
    while blockchain_writer not in SUPPORTED_UTXO_PROVIDERS:
        if not(interactive or force):
            raise Exception('No blockchain reader given')

        # prompt for it?
        blockchain_message = (
            'NOTE: Blockstack currently requires an external API\n'
            'for sending transactions to the blockchain.  The set\n'
            'of supported service providers are:\n'
            '\t\n'.join(SUPPORTED_UTXO_PROVIDERS) + '\n'
            'Please enter the requisite information here.'
        )
        blockchain_writer_dict = interactive_prompt(blockchain_message, ['blockchain_writer'], {})
        blockchain_writer = blockchain_writer_dict['blockchain_writer']

    blockchain_writer_defaults = default_utxo_provider_opts(blockchain_writer, config_file=config_file)
    blockchain_writer_defaults.update(all_opts.get('blockchain_write', {}))
    blockchain_writer_params = SUPPORTED_UTXO_PARAMS[blockchain_writer]

    # get current set of writer opts
    blockchain_writer_opts = {} if force else copy.deepcopy(blockchain_writer_defaults)

    blockchain_writer_opts, missing_writer_opts, num_writer_opts_prompted = find_missing(
        SUPPORTED_UTXO_PROMPT_MESSAGES[blockchain_writer],
        blockchain_writer_params,
        blockchain_writer_opts,
        blockchain_writer_defaults,
        header='Blockchain writer configuration',
        prompt_missing=interactive
    )

    blockchain_writer_opts['utxo_provider'] = blockchain_writer_defaults['utxo_provider']

    missing_opts = [missing_bitcoin_opts, missing_writer_opts, missing_reader_opts, missing_blockstack_opts]
    if not interactive and any(missing_opts):
        # cannot continue
        raise Exception(
            'Missing configuration fields: {}'.format(
                ','.join(list(itertools.chain(*missing_opts)))
            )
        )

    # ask for contact info, so we can send out notifications for bugfixes and
    # upgrades
    if blockstack_opts.get('email') is None:
        if interactive:
            email_msg = (
                'Would you like to receive notifications\n'
                'from the developers when there are critical\n'
                'updates available to install?\n\n'
                'If so, please enter your email address here.\n'
                'If not, leave this field blank.\n\n'
                'Your email address will be used solely\n'
                'for this purpose.\n'
            )
            email_opts, _, email_prompted = find_missing(
                email_msg, ['email'], {}, {'email': ''}, prompt_missing=interactive
            )

            # merge with blockstack section
            num_blockstack_opts_prompted += 1
            blockstack_opts['email'] = email_opts['email']

        else:
            num_blockstack_opts_prompted += 1
            blockstack_opts['email'] = ''

    u = get_or_set_uuid(config_dir=config_dir)
    if u is None:
        raise Exception('Failed to get/set UUID')

    ret = {
        'blockstack-client': blockstack_opts,
        'bitcoind': bitcoind_opts,
        'blockchain-reader': blockchain_reader_opts,
        'blockchain-writer': blockchain_writer_opts,
        'subdomain-resolution' : subdomain_opts
    }

    # if we prompted, then save
    if any([num_bitcoind_prompted, num_reader_opts_prompted, num_writer_opts_prompted, num_blockstack_opts_prompted]):
        print('Saving configuration to {}'.format(config_file), file=sys.stderr)

        # rename appropriately, so other packages can find them
        write_config_file(ret, config_file)

    # preserve these extra helper fields
    ret['blockstack-client']['path'] = config_file
    if config_file is not None:
        ret['blockstack-client']['dir'] = os.path.dirname(config_file)
    else:
        ret['blockstack-client']['dir'] = None

    # set this here, so we don't save it
    ret['uuid'] = u
    
    if set_migrate:
        ret['migrated'] = migrated

    return ret


def clear_runtime_fields(opts):
    """
    Remove runtime opts from a config dict.
    """
    for opt in ['path', 'dir', 'migrated', 'uuid']:
        if opts.has_key(opt):
            del opts[opt]

    return opts


def write_config_file(opts, config_file):
    """
    Write our config file with the given options dict.
    Each key is a section name, and each value is the list of options.

    If the file exists, do not remove unaffected sections.  Instead,
    merge the sections in opts into the file.

    Return True on success
    Raise on error
    """

    if 'blockstack-client' in opts:
        opts['blockstack-client'] = clear_runtime_fields(opts['blockstack-client'])

    opts = clear_runtime_fields(opts)

    parser = SafeConfigParser()

    if os.path.exists(config_file):
        parser.read(config_file)

    for sec_name in opts:
        sec_opts = opts[sec_name]

        if parser.has_section(sec_name):
            parser.remove_section(sec_name)

        parser.add_section(sec_name)
        for opt_name, opt_value in sec_opts.items():
            if opt_value is None:
                opt_value = ''

            parser.set(sec_name, opt_name, '{}'.format(opt_value))

    with open(config_file, 'w') as fout:
        os.fchmod(fout.fileno(), 0600)
        parser.write(fout)

    return True


def write_config_section(config_path, section_name, section_data ):
    """
    Write a whole config section.
    Overwrite it if it exists.
    Return True on success
    Return False on failure
    """
    if not os.path.exists(config_path):
        return False

    parser = SafeConfigParser()
    parser.read(config_path)

    if not parser.has_section(section_name):
        parser.add_section(section_name)

    for field_name, field_value in section_data.items():
        parser.set(section_name, field_name, field_value)

    with open(config_path, 'w') as fout:
        os.fchmod(fout.fileno(), 0600)
        parser.write(fout)

    return True


def write_config_field(config_path, section_name, field_name, field_value):
    """
    Set a particular config file field
    Return True on success
    Return False on error
    """
    if not os.path.exists(config_path):
        return False

    parser = SafeConfigParser()
    parser.read(config_path)

    if not parser.has_section(section_name):
        parser.add_section(section_name)
        
    parser.set(section_name, field_name, '{}'.format(field_value))
    with open(config_path, 'w') as fout:
        os.fchmod(fout.fileno(), 0600)
        parser.write(fout)

    return True


def delete_config_field(config_path, section_name, field_name ):
    """
    Delete a config field
    Return True on success
    Return False on error
    """
    if not os.path.exists(config_path):
        return False

    parser = SafeConfigParser()
    parser.read(config_path)

    parser.remove_option(section_name, field_name)
    with open(config_path, 'w') as fout:
        os.fchmod(fout.fileno(), 0600)
        parser.write(fout)

    return True


def delete_config_section(config_path, section_name):
    """
    Delete a config section
    Return True on success
    Return False on error
    """
    if not os.path.exists(config_path):
        return False

    parser = SafeConfigParser()
    parser.read(config_path)

    parser.remove_section(section_name)
    with open(config_path, 'w') as fout:
        os.fchmod(fout.fileno(), 0600)
        parser.write(fout)

    return True


def get_utxo_provider_client(config_path=CONFIG_PATH, min_confirmations=TX_MIN_CONFIRMATIONS):
    """
    Get or instantiate our blockchain UTXO provider's client.
    Return None if we were unable to connect
    """

    # acquire configuration (which we should already have)
    opts = configure(interactive=False, config_file=config_path)
    reader_opts = opts['blockchain-reader']

    try:
        utxo_provider = connect_utxo_provider(reader_opts, min_confirmations=min_confirmations)
        return utxo_provider
    except Exception as e:
        log.exception(e)
        return

    return

def get_subdomains_db_path(config_path=CONFIG_PATH):
    opts = configure(interactive=False, config_file=config_path)
    subdomain_opts = opts['subdomain-resolution']
    return subdomain_opts['subdomains_db']

def get_is_resolving_subdomains(config_path=CONFIG_PATH):
    opts = configure(interactive=False, config_file=config_path)
    subdomain_opts = opts['subdomain-resolution']
    return subdomain_opts.get('resolving_subdomains', False)

def get_tx_broadcaster(config_path=CONFIG_PATH):
    """
    Get or instantiate our blockchain UTXO provider's transaction broadcaster.
    fall back to the utxo provider client, if one is not designated
    """

    # acquire configuration (which we should already have)
    opts = configure(interactive=False, config_file=config_path)
    writer_opts = opts['blockchain-writer']

    try:
        blockchain_broadcaster = connect_utxo_provider(writer_opts)
        return blockchain_broadcaster
    except Exception as e:
        log.exception(e)
        return

    return


def str_to_bool(s):
    """
    Convert 'true' to True; 'false' to False
    """
    if type(s) not in [str, unicode]:
        raise ValueError('"{}" is not a string'.format(s))

    if s.lower() == 'false':
        return False
    elif s.lower() == 'true':
        return True
    else:
        raise ValueError('Indeterminate boolean "{}"'.format(s))


def read_config_file(config_path=CONFIG_PATH, set_migrate=False):
    """
    Read or make a new empty config file with sane defaults.
    Automatically convert legacy config field and values into their current equivalents.
    If set_migrate is True, then include 'set_migrate: True/False' in the top-level dict returned
    in order to indicate whether or not any config field migration took place.

    Return the config dict on success
    Raise on error
    """
    global CONFIG_PATH, BLOCKSTACKD_SERVER, BLOCKSTACKD_PORT

    BLOCKSTACK_CLI_SERVER_HOST = os.environ.get('BLOCKSTACK_CLI_SERVER_HOST', None)     # overrides config file
    BLOCKSTACK_CLI_SERVER_PORT = os.environ.get('BLOCKSTACK_CLI_SERVER_PORT', None)     # overrides config file
    BLOCKSTACK_CLI_SERVER_PROTOCOL = os.environ.get('BLOCKSTACK_CLI_SERVER_PROTOCOL', None)

    if BLOCKSTACK_CLI_SERVER_PORT is not None:
        try:
            BLOCKSTACK_CLI_SERVER_PORT = BLOCKSTACK_CLI_SERVER_PORT
        except:
            raise Exception("Invalid server port")

    # try to create
    if config_path is not None:
        dirname = os.path.dirname(config_path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        if not os.path.isdir(dirname):
            raise Exception('Not a directory: {}'.format(config_path))

    client_uuid = get_or_set_uuid(config_dir=os.path.dirname(config_path))
    if client_uuid is None:
        raise Exception("Failed to get client device ID")

    config_dir = os.path.dirname(config_path)
    if config_path is None or not os.path.exists(config_path):

        # make a new config structure and save it
        parser = SafeConfigParser()
        parser.add_section('blockstack-client')
        parser.set('blockstack-client', 'server', str(BLOCKSTACKD_SERVER))
        parser.set('blockstack-client', 'port', str(BLOCKSTACKD_PORT))
        parser.set('blockstack-client', 'protocol', 'https')
        parser.set('blockstack-client', 'metadata', METADATA_DIRNAME)
        parser.set('blockstack-client', 'storage_drivers', BLOCKSTACK_DEFAULT_STORAGE_DRIVERS)
        parser.set('blockstack-client', 'storage_drivers_required_write', BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE)
        parser.set('blockstack-client', 'api_endpoint_port', str(DEFAULT_API_PORT))
        parser.set('blockstack-client', 'api_endpoint_host', DEFAULT_API_HOST)
        parser.set('blockstack-client', 'api_endpoint_bind', DEFAULT_API_HOST)
        parser.set('blockstack-client', 'queue_path', str(DEFAULT_QUEUE_PATH))
        parser.set('blockstack-client', 'poll_interval', str(DEFAULT_POLL_INTERVAL))
        parser.set('blockstack-client', 'blockchain_reader', DEFAULT_BLOCKCHAIN_READER)
        parser.set('blockstack-client', 'blockchain_writer', DEFAULT_BLOCKCHAIN_WRITER)
        parser.set('blockstack-client', 'anonymous_statistics', 'True')
        parser.set('blockstack-client', 'client_version', VERSION)

        api_pass = os.urandom(32)
        parser.set('blockstack-client', 'api_password', hexlify(api_pass))

        if config_path is not None:
            try:
                with open(config_path, 'w') as f:
                    parser.write(f)
                    f.flush()

            except:
                traceback.print_exc()
                log.error('Failed to write default configuration file to "{}".'.format(config_path))
                return False

        parser.add_section('blockchain-reader')
        parser.set('blockchain-reader', 'utxo_provider', DEFAULT_BLOCKCHAIN_READER)

        parser.add_section('blockchain-writer')
        parser.set('blockchain-writer', 'utxo_provider', DEFAULT_BLOCKCHAIN_WRITER)

        parser.add_section('bitcoind')

        bitcoind_config = default_bitcoind_opts()
        for k, v in bitcoind_config.items():
            if v is not None:
                parser.set('bitcoind', k, '{}'.format(v))

        parser.add_section('subdomain-resolution')
        parser.set('subdomain-resolution', 'subdomains_db', str(config_dir) + "/subdomains.db")

        # save
        if config_path is not None:
            with open(config_path, 'w') as f:
                parser.write(f)
                f.flush()

    # now read it back
    parser = SafeConfigParser()
    parser.read(config_path)

    # these are booleans--convert them
    bool_values = {
        'blockstack-client': [
            'anonymous_statistics',
        ]
    }

    ret = {}
    for sec in parser.sections():
        ret[sec] = {}
        for opt in parser.options(sec):
            if opt in bool_values.get(sec, {}):
                # decode to bool
                ret[sec][opt] = str_to_bool(parser.get(sec, opt))
            else:
                # literal
                ret[sec][opt] = parser.get(sec, opt)

    # convert field names
    renamed_fields_014_1 = {
        'blockstack-client': {
            'rpc_token': 'api_pass',        # renamed in 0.14.1
        },
    }

    dropped_fields_014_1 = {
        'blockstack-client': [
            'blockchain_headers',
        ],
    }

    added_fields_014_1 = {
        'bitcoind': {
            'spv_path': os.path.expanduser('~/.virtualchain-spv-headers.dat'),  # from virtualchain
        },
    }

    changed_fields_014_1 = {
        'blockstack-client': {
            'client_version': VERSION
        }
    }

    renamed_fields_014_4 = {}
    dropped_fields_014_4 = {}
    changed_fields_014_4 = {}
    added_fields_014_4 = {
        'subdomain-resolution': {
            'subdomains_db' : str(config_dir) + "/subdomains.db"
        },
    }

    # add HTTPS support in 0.14.4.3
    renamed_fields_014_4_3 = {}
    dropped_fields_014_4_3 = {}

    if ret['blockstack-client']['server'] == 'node.blockstack.org':
        blockstackd_port_default = 6263
    else:
        blockstackd_port_default = 6264

    changed_fields_014_4_3 = {
        'blockstack-client': {
            'port' : (str(6264), str(blockstackd_port_default))
        }
    }

    # should only default to https if we also are pointed at node.blockstack.org
    if ret['blockstack-client']['server'] == 'node.blockstack.org':
        protocol_default = 'https'
    else:
        protocol_default = 'http'
    added_fields_014_4_3 = {
        'blockstack-client': {
            'protocol' : protocol_default
        }
   }

    # grow this list with future releases...
    renamed_fields = [renamed_fields_014_1, renamed_fields_014_4, renamed_fields_014_4_3]
    removed_fields = [dropped_fields_014_1, dropped_fields_014_4, dropped_fields_014_4_3]
    added_fields = [added_fields_014_1, added_fields_014_4, added_fields_014_4_3]
    changed_fields = [changed_fields_014_1, changed_fields_014_4, changed_fields_014_4_3]

    migrated = False

    assert len(renamed_fields) == len(removed_fields)
    assert len(removed_fields) == len(added_fields)
    assert len(added_fields) == len(changed_fields)

    for i in xrange(0, len(renamed_fields)):
        # order: rename, add, drop, change
        renamed_field_set = renamed_fields[i]
        dropped_field_set = removed_fields[i]
        added_field_set = added_fields[i]
        changed_field_set = changed_fields[i]

        for sec in renamed_field_set.keys():
            if ret.has_key(sec):
                for old_field_name in renamed_field_set[sec].keys():
                    if ret[sec].has_key( old_field_name ):
                        new_field_name = renamed_field_set[sec][old_field_name]
                        value = ret[sec][old_field_name]

                        log.debug("Migrate {}.{} to {}.{}".format(sec, old_field_name, sec, new_field_name))

                        del ret[sec][old_field_name]
                        ret[sec][new_field_name] = value

                        migrated = True

        for sec in added_field_set.keys():
            if not ret.has_key(sec):
                ret[sec] = {}

            for new_field_name in added_field_set[sec].keys():
                if not ret[sec].has_key(new_field_name):

                    log.debug("Add new field {}.{}".format(sec, new_field_name))
                    ret[sec][new_field_name] = added_field_set[sec][new_field_name]

                    migrated = True

        for sec in dropped_field_set.keys():
            if ret.has_key(sec):
                for dropped_field_name in dropped_field_set[sec]:
                    if ret[sec].has_key(dropped_field_name):

                        log.debug("Remove old field {}.{}".format(sec, dropped_field_name))
                        del ret[sec][dropped_field_name]

                        migrated = True

        for sec in changed_field_set.keys():
            if not ret.has_key(sec):
                ret[sec] = {}

            for changed_field_name in changed_field_set[sec]:
                changed_field_value = changed_field_set[sec][changed_field_name]
                if isinstance(changed_field_value, tuple):
                    prior_default, new_default = changed_field_value
                    old_value = ret[sec][changed_field_name]
                    if old_value == prior_default and old_value != new_default:

                        # don't go overboard
                        if not (sec == 'blockstack-client' and changed_field_name == 'client_version'):
                            log.debug("Change {}.{} to {}".format(sec, changed_field_name, new_default))

                        ret[sec][changed_field_name] = new_default
                        migrated = True

                elif ret[sec][changed_field_name] != changed_field_value:

                    # don't go overboard
                    if not (sec == 'blockstack-client' and changed_field_name == 'client_version'):
                        log.debug("Change {}.{} to {}".format(sec, changed_field_name, changed_field_value))

                    ret[sec][changed_field_name] = changed_field_value
                    migrated = True

    # overrides from the environment
    env_overrides = {
        'blockstack-client': {
            'server': BLOCKSTACK_CLI_SERVER_HOST,
            'port': BLOCKSTACK_CLI_SERVER_PORT,
            'protocol': BLOCKSTACK_CLI_SERVER_PROTOCOL,
        },
    }

    for sec in env_overrides.keys():
        if ret.has_key(sec):
            for field_name in env_overrides[sec].keys():
                new_value = env_overrides[sec][field_name]
                if new_value is not None and new_value != ret[sec][field_name]:
                    log.debug("Override {}.{} from {} to {}".format(sec, field_name, ret[sec][field_name], new_value))
                    ret[sec][field_name] = new_value

    # force client:port to int
    if 'blockstack-client' in ret:
        ret['blockstack-client']['port'] = int(ret['blockstack-client']['port'])

    # helpful at runtime
    ret['path'] = config_path
    ret['dir'] = os.path.dirname(config_path)

    if set_migrate:
        ret['migrated'] = migrated

    return ret


def get_config(path=CONFIG_PATH, interactive=False):
    """
    Read our config file (legacy compat).
    Flatten the resulting config:
    * make all bitcoin-specific fields start with 'bitcoind_' (makes this config compatible with virtualchain)
    * keep only the blockstack-client and bitcoin fields

    Return our flattened configuration (as a dict) on success.
    Return None on error
    """

    try:
        opts = configure(config_file=path, interactive=interactive)
    except Exception as e:
        log.exception(e)
        return None

    # flatten
    blockstack_opts = opts['blockstack-client']
    bitcoin_opts = opts['bitcoind']

    bitcoin_opts = opt_restore('bitcoind_', bitcoin_opts)
    blockstack_opts.update(bitcoin_opts)

    # pass along the config path and dir, and statistics info
    blockstack_opts['path'] = path
    blockstack_opts['dir'] = os.path.dirname(path)
    blockstack_opts['uuid'] = opts['uuid']
    blockstack_opts['client_version'] = blockstack_opts.get('client_version', '')
    if 'anonymous_statistics' not in blockstack_opts:
        # not disabled
        blockstack_opts['anonymous_statistics'] = True

    return blockstack_opts


def setup_config(config_path=CONFIG_PATH, interactive=False):
    """
    Set up our config file:
    * create it if it doesn't exist
    * migrate field names and values
    * back up the old config file if we changed anything during migration.

    Return {'status': True, 'config': ..., 'migrated': True/False, 'backup_path': ...} on success
    Return {'error': ...} on failure
    """
 
    conf = configure(config_file=config_path, interactive=interactive, set_migrate=True)
    if conf is None:
        return {'error': 'Failed to load config'}

    conf_migrated = conf['migrated']
    del conf['migrated']

    conf_backed_up = False
    backup_path = None
    conf_version = conf['blockstack-client'].get('client_version', '')
    if conf_version != VERSION:
        # back up the config file 
        backup_path = backup_config_file(config_path=config_path)
        if not backup_path:
            return {'error': 'Failed to load backup path'}

        else:
            conf_backed_up = True

    if conf_migrated:
        log.warning("Migrating config file...") 
        if not conf_backed_up:
            # back up the config file 
            backup_path = backup_config_file(config_path=config_path)
            if not backup_path:
                return {'error': 'Failed to load backup path'}

        # save config file
        try:
            write_config_file(conf, config_path)
        except Exception as e:
            log.exception(e)
            return {'error': 'Failed to save new config file'}

    return {'status': True, 'config': conf, 'migrated': conf_migrated, 'backup_path': backup_path}


def get_version_parts(whole, func):
    return [func(_.strip()) for _ in whole[0:3]]


def semver_match(v1, v2):
    """
    Verify that two semantic version strings match:
    the major and the minor versions must be equal.
    Patch versions can be different
    """
    v1_parts = v1.split('.')
    v2_parts = v2.split('.')
    if len(v1_parts) < 3 or len(v2_parts) < 3:
        # one isn't a semantic version
        return False

    v1_major, v1_minor, v1_patch = get_version_parts(v1_parts, str)
    v2_major, v2_minor, v2_patch = get_version_parts(v2_parts, str)

    # NOTE: patch versions are not relevant here.
    return [v1_major, v1_minor] == [v2_major, v2_minor]


def semver_newer(v1, v2):
    """
    Verify (as semantic versions) if v1 < v2
    Patch versions can be different
    """
    v1_parts = v1.split('.')
    v2_parts = v2.split('.')
    if len(v1_parts) < 3 or len(v2_parts) < 3:
        # one isn't a semantic version
        return False

    v1_major, v1_minor, v1_patch = get_version_parts(v1_parts, int)
    v2_major, v2_minor, v2_patch = get_version_parts(v2_parts, int)

    if v1_major > v2_major:
        return False

    if v1_major == v2_major and v1_minor >= v2_minor:
        return False

    return True


def backup_config_file(config_path=CONFIG_PATH):
    """
    Back up the given config file
    Return the backup file
    """
    if not os.path.exists(config_path):
        return None

    legacy_path = config_path + ".legacy.{}".format(int(time.time()))
    while os.path.exists(legacy_path):
        time.sleep(1.0)
        legacy_path = config_path + ".legacy.{}".format(int(time.time()))

    log.warning('Back up old config file from {} to {}'.format(config_path, legacy_path))
    shutil.copy(config_path, legacy_path)
    return legacy_path


def configure_zonefile(name, zonefile, data_pubkey ):
    """
    Given a name and zonefile, help the user configure the
    zonefile information to store (just URLs for now).

    @zonefile must be parsed and must be a dict.

    Return the new zonefile on success
    Return None if the zonefile did not change.
    """

    from .zonefile import make_empty_zonefile
    from .user import user_zonefile_data_pubkey, user_zonefile_set_data_pubkey, user_zonefile_remove_data_pubkey, \
            user_zonefile_urls, add_user_zonefile_url, remove_user_zonefile_url, swap_user_zonefile_urls, \
            add_user_zonefile_txt, remove_user_zonefile_txt, user_zonefile_txts

    from .storage import get_drivers_for_url

    if zonefile is None:
        print('WARNING: No zonefile could be found.')
        print('WARNING: Creating an empty zonefile.')
        zonefile = make_empty_zonefile(name, data_pubkey)

    running = True
    do_update = True
    old_zonefile = {}
    old_zonefile.update( zonefile )

    while running:
        public_key = None
        try:
            public_key = user_zonefile_data_pubkey(zonefile) 
        except ValueError:
            # multiple keys
            public_key = None

        urls = user_zonefile_urls(zonefile) 
        if urls is None:
            urls = []

        txts = user_zonefile_txts(zonefile)
        if txts is None:
            txts = []

        url_drivers = {}

        # which drivers?
        for url in urls:
            drivers = get_drivers_for_url(url)
            url_drivers[url] = drivers

        print('-' * 80)

        if public_key is not None:
            print('Data public key: {}'.format(public_key))
        else:
            print('Data public key: (not set)')

        print('')
        print('Profile replicas ({}):'.format(len(urls)))
        if len(urls) > 0:
            for i in xrange(0, len(urls)):
                url = urls[i]
                drivers = get_drivers_for_url(url)
                print('({}) {}\n    Handled by drivers: [{}]'.format(i+1, url, ','.join([d.__name__ for d in drivers])))

        else:
            print('(none)')

        print('')
    
        # don't count the public key...
        print("TXT records ({}):".format(len(txts) - (1 if public_key else 0)))
        if len(txts) > 0:
            for i in xrange(0, len(txts)):
                # skip public key
                if txts[i]['name'] == 'pubkey':
                    continue

                print('{} "{}"'.format(txts[i]['name'], txts[i]['txt']))

        else:
            print("(none)")

        print('')
        print('What would you like to do?')
        print('(a) Add profile URL')
        print('(b) Remove profile URL')
        print('(c) Swap URL order')
        print('(d) Add TXT record')
        print('(e) Remove TXT record')
        print('(f) Set or change public key')
        print('(g) Save zonefile')
        print('(h) Do not save zonefile')
        print('')

        selection = raw_input('Selection: ').lower()

        if selection == 'h':
            do_update = False
            break

        elif selection == 'a':
            # add a url 
            while True:
                try:
                    new_url = raw_input('Enter the new profile URL: ')
                except KeyboardInterrupt:
                    print('Keyboard interrupt')
                    return None

                new_url = new_url.strip()

                # do any drivers accept this URL?
                drivers = get_drivers_for_url( new_url )
                if len(drivers) == 0:
                    print('No drivers can handle "{}"'.format(new_url))
                    continue

                else:
                    # add to the zonefile
                    new_zonefile = add_user_zonefile_url( zonefile, new_url )
                    if new_zonefile is None:
                        print('Duplicate URL')
                        continue

                    else:
                        zonefile = new_zonefile
                        break


        elif selection == 'b':
            # remove a URL
            url_to_remove = None
            while True:
                try:
                    url_to_remove = raw_input('Which URL do you want to remove? ({}-{}): '.format(1, len(urls)))
                    try:
                        url_to_remove = int(url_to_remove)
                        assert 1 <= url_to_remove and url_to_remove <= len(urls)
                    except:
                        print('Bad selection')
                        continue

                except KeyboardInterrupt:
                    running = False
                    print('Keyboard interrupt')
                    return None

                if url_to_remove is not None:
                    # remove this URL 
                    url = urls[url_to_remove-1]
                    
                    log.debug("Remove '{}'".format(url))

                    new_zonefile = remove_user_zonefile_url( zonefile, url )
                    if new_zonefile is None:
                        print('BUG: failed to remove url "{}" from zonefile\n{}\n'.format(url, json.dumps(zonefile, indent=4, sort_keys=True)))
                        os.abort()

                    else:
                        zonefile = new_zonefile
                        break

                else:
                    print("Bad selection")

        elif selection == 'c':
            while True:
                # swap order
                try:
                    url_1 = raw_input('Which URL do you want to move? ({}-{}): '.format(1, len(urls)))
                    url_2 = raw_input('Where do you want to move it?  ({}-{}): '.format(1, len(urls)))
                except KeyboardInterrupt:
                    running = False
                    print('Keyboard interrupt')
                    return None

                try:
                    url_1 = int(url_1)
                    url_2 = int(url_2)

                    assert 1 <= url_1 <= len(urls)
                    assert 1 <= url_2 <= len(urls)
                    assert url_1 != url_2

                except:
                    print("Bad selection")
                    continue
                
                new_zonefile = swap_user_zonefile_urls( zonefile, url_1-1, url_2-1 )
                if new_zonefile is None:
                    print('BUG: failed to remove url "{}" from zonefile\n{}\n'.format(url, json.dumps(zonefile, indent=4, sort_keys=True)))
                    os.abort()

                else:
                    zonefile = new_zonefile
                    break


        elif selection == 'd':
            # add txt record 
            while True:
                try:
                    txtrec_name = raw_input("New TXT record name: ")
                    txtrec_txt = raw_input("New TXT record data: ")
                except KeyboardInterrupt:
                    running = False
                    print("Keyboard interrupt")
                    return None

                if txtrec_name == 'pubkey':
                    print("Change the ECDSA key explicitly")
                    break

                new_zonefile = add_user_zonefile_txt(zonefile, txtrec_name, txtrec_txt)
                if new_zonefile is None:
                    print("Duplicate TXT record")
                    break

                else:
                    zonefile = new_zonefile
                    break


        elif selection == 'e':
            # remove txt record 
            while True:
                try:
                    txtrec_name = raw_input('Name of TXT record to remove: ')
                except KeyboardInterrupt:
                    running = False
                    print("Keyboard interrupt")
                    return None

                if txtrec_name == 'pubkey':
                    print("Change the ECDSA key explicitly")
                    break

                new_zonefile = remove_user_zonefile_txt(zonefile, txtrec_name)
                if new_zonefile is None:
                    print("No such TXT record")
                    break

                else:
                    zonefile = new_zonefile
                    break

        elif selection == 'f':
            # change public key 
            while True:
                try:
                    pubkey = raw_input("New ECDSA public key (empty for None): ")

                    if len(pubkey) > 0:
                        pubkey = keylib.ECPublicKey(pubkey).to_hex()

                except KeyboardInterrupt:
                    running = False
                    print("Keyboard interrupt")
                    return None

                except:
                    print("Invalid public key")
                    continue

                new_zonefile = None

                if len(pubkey) == 0:
                    # delete public key
                    new_zonefile = user_zonefile_remove_data_pubkey(zonefile)

                else:
                    # set public key 
                    new_zonefile = user_zonefile_set_data_pubkey(zonefile, pubkey)

                zonefile = new_zonefile
                break

        elif selection == 'g':
            # save zonefile
            break

        elif selection == 'h':
            # do not save zonefile 
            return None

        log.debug("zonefile is now:\n{}".format(json.dumps(zonefile, indent=4, sort_keys=True)))

    return zonefile
