#!/usr/bin/env python
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
import itertools
import logging
import traceback
import uuid
import urllib2
from binascii import hexlify
from ConfigParser import SafeConfigParser

import virtualchain
from .backend.utxo import *
from .constants import *

def get_logger(name="blockstack-client", debug=DEBUG):
    logger = virtualchain.get_logger(name)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    return logger

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


def url_to_host_port(url, port=DEFAULT_BLOCKSTACKD_PORT):
    """
    Given a URL, turn it into (host, port).
    Return (None, None) on invalid URL
    """
    if not url.startswith('http://') or not url.startswith('https://'):
        url = 'http://' + url

    urlinfo = urllib2.urlparse.urlparse(url)
    hostport = urlinfo.netloc

    parts = hostport.split('@')
    if len(parts) > 2:
        return None, None

    if len(parts) == 2:
        hostport = parts[1]

    parts = hostport.split(':')
    if len(parts) > 2:
        return None, None

    if len(parts) == 2:
        try:
            port = int(parts[1])
            assert 0 < port < 65535, 'Invalid port'
        except TypeError:
            return None, None

    return parts[0], port


def atlas_inventory_to_string( inv ):
    """
    Inventory to string (bitwise big-endian)
    """
    ret = ""
    for i in xrange(0, len(inv)):
        for j in xrange(0, 8):
            bit_index = 1 << (7 - j)
            val = (ord(inv[i]) & bit_index)
            if val != 0:
                ret += "1"
            else:
                ret += "0"

    return ret


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


def get_all_device_ids(config_path=CONFIG_PATH):
    """
    Get the list of all device IDs that use this wallet
    The first device ID is guaranteed to be the local device ID
    """
    local_device_id = get_local_device_id(config_dir=os.path.dirname(config_path))
    device_ids = [local_device_id]
    
    conf = get_config(config_path)
    assert conf

    if conf.has_key('default_devices'):
        device_ids += filter(lambda x: len(x) > 0, conf['default_devices'].split(','))

    return device_ids


def configure(config_file=CONFIG_PATH, force=False, interactive=True):
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

    global SUPPORTED_UTXO_PROVIDERS, SUPPORTED_UTXO_PARAMS, SUPPORTED_UTXO_PROMPT_MESSAGES

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

    blockstack_opts = {}
    blockstack_opts_defaults = read_config_file(path=config_file)['blockstack-client']
    blockstack_params = blockstack_opts_defaults.keys()

    if not force:
        # defaults
        blockstack_opts = read_config_file(path=config_file)['blockstack-client']

    blockstack_opts, missing_blockstack_opts, num_blockstack_opts_prompted = find_missing(
        blockstack_message,
        blockstack_params,
        blockstack_opts,
        blockstack_opts_defaults,
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
    bitcoind_params = bitcoind_opts_defaults.keys()

    if not force:
        # get default set of bitcoind opts
        bitcoind_opts = default_bitcoind_opts(config_file=config_file)

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
    blockchain_reader_params = SUPPORTED_UTXO_PARAMS[blockchain_reader]

    # get current set of reader opts
    blockchain_reader_opts = {} if force else blockchain_reader_defaults

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
    blockchain_writer_params = SUPPORTED_UTXO_PARAMS[blockchain_writer]

    # get current set of writer opts
    blockchain_writer_opts = {} if force else blockchain_writer_defaults

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

    # get client UUID for analytics
    u = get_or_set_uuid(config_dir=config_dir)
    if u is None:
        raise Exception('Failed to get/set UUID')

    ret = {
        'blockstack-client': blockstack_opts,
        'bitcoind': bitcoind_opts,
        'blockchain-reader': blockchain_reader_opts,
        'blockchain-writer': blockchain_writer_opts
    }

    # if we prompted, then save
    if any([num_bitcoind_prompted, num_reader_opts_prompted, num_writer_opts_prompted, num_blockstack_opts_prompted]):
        print('Saving configuration to {}'.format(config_file), file=sys.stderr)

        # rename appropriately, so other packages can find them
        write_config_file(ret, config_file)

    # preserve these extra helper fields
    blockstack_opts['path'] = config_file
    if config_file is not None:
        blockstack_opts['dir'] = os.path.dirname(config_file)
    else:
        blockstack_opts['dir'] = None

    # set this here, so we don't save it
    ret['uuid'] = u
    return ret


def write_config_file(opts, config_file):
    """
    Write our config file with the given options dict.
    Each key is a section name, and each value is the list of options.

    Return True on success
    Raise on error
    """

    if 'blockstack-client' in opts:
        assert 'path' not in opts['blockstack-client']
        assert 'dir' not in opts['blockstack-client']

    assert 'path' not in opts
    assert 'dir' not in opts

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


def set_advanced_mode(status, config_path=CONFIG_PATH):
    """
    Enable or disable advanced mode
    @status must be a bool
    """
    return write_config_field(config_path, 'blockstack-client', 'advanced_mode', str(status))


def get_utxo_provider_client(config_path=CONFIG_PATH):
    """
    Get or instantiate our blockchain UTXO provider's client.
    Return None if we were unable to connect
    """

    # acquire configuration (which we should already have)
    opts = configure(interactive=False, config_file=config_path)
    reader_opts = opts['blockchain-reader']

    try:
        utxo_provider = connect_utxo_provider(reader_opts)
        return utxo_provider
    except Exception as e:
        log.exception(e)
        return

    return


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


def read_config_file(path=CONFIG_PATH):
    """
    Read or make a new empty config file with sane defaults.
    Return the config dict on success
    Raise on error
    """
    global CONFIG_PATH, BLOCKSTACKD_SERVER, BLOCKSTACKD_PORT

    # try to create
    if path is not None:
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        if not os.path.isdir(dirname):
            raise Exception('Not a directory: {}'.format(path))

    client_uuid = get_or_set_uuid(config_dir=os.path.dirname(path))
    if client_uuid is None:
        raise Exception("Failed to get client device ID")

    config_dir = os.path.dirname(path)
    if path is None or not os.path.exists(path):

        parser = SafeConfigParser()
        parser.add_section('blockstack-client')
        parser.set('blockstack-client', 'server', str(BLOCKSTACKD_SERVER))
        parser.set('blockstack-client', 'port', str(BLOCKSTACKD_PORT))
        parser.set('blockstack-client', 'metadata', METADATA_DIRNAME)
        parser.set('blockstack-client', 'storage_drivers', BLOCKSTACK_DEFAULT_STORAGE_DRIVERS)
        parser.set('blockstack-client', 'storage_drivers_local', 'disk')
        parser.set('blockstack-client', 'storage_drivers_required_write', BLOCKSTACK_REQUIRED_STORAGE_DRIVERS_WRITE)
        parser.set('blockstack-client', 'advanced_mode', 'false')
        parser.set('blockstack-client', 'api_endpoint_port', str(DEFAULT_API_PORT))
        parser.set('blockstack-client', 'queue_path', str(DEFAULT_QUEUE_PATH))
        parser.set('blockstack-client', 'poll_interval', str(DEFAULT_POLL_INTERVAL))
        parser.set('blockstack-client', 'blockchain_reader', DEFAULT_BLOCKCHAIN_READER)
        parser.set('blockstack-client', 'blockchain_writer', DEFAULT_BLOCKCHAIN_WRITER)
        parser.set('blockstack-client', 'anonymous_statistics', 'True')
        parser.set('blockstack-client', 'client_version', VERSION)
        parser.set('blockstack-client', 'default_devices', '')

        api_pass = os.urandom(32)
        parser.set('blockstack-client', 'api_password', hexlify(api_pass))

        if path is not None:
            try:
                with open(path, 'w') as f:
                    parser.write(f)
                    f.flush()
                    os.fsync(f.fileno())

            except:
                traceback.print_exc()
                log.error('Failed to write default configuration file to "{}".'.format(path))
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

        # save
        if path is not None:
            with open(path, 'w') as f:
                parser.write(f)
                f.flush()
                os.fsync(f.fileno())

    # now read it back
    parser = SafeConfigParser()
    parser.read(path)

    # these are booleans--convert them
    bool_values = {
        'blockstack-client': [
            'advanced_mode',
            'anonymous_statistics',
            'authenticate_api',
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

    if 'advanced_mode' not in ret.get('blockstack-client', {}):
        ret['blockstack-client']['advanced_mode'] = False

    # convert field names
    renamed_fields_014_1 = {
        'blockstack-client': {
            'rpc_token': 'api_pass',        # renamed in 0.14.1
        },
    }

    renamed_fields = [renamed_fields_014_1]

    for renamed_field_set in renamed_fields:
        for sec in renamed_field_set.keys():
            if ret.has_key(sec):
                for old_field_name in renamed_field_set[sec].keys():
                    if ret[sec].has_key( old_field_name ):
                        new_field_name = renamed_field_set[sec][old_field_name]

                        value = ret[sec][old_field_name]
                        del ret[sec][old_field_name]
                        ret[sec][new_field_name] = value
    
    ret['path'] = path
    ret['dir'] = os.path.dirname(path)

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
    shutil.move(config_path, legacy_path)
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
    from .user import user_zonefile_data_pubkey, user_zonefile_urls, add_user_zonefile_url, remove_user_zonefile_url, swap_user_zonefile_urls
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
        print('What would you like to do?')
        print('(a) Add profile URL')
        print('(b) Remove profile URL')
        print('(c) Swap URL order')
        print('(d) Save zonefile')
        print('(e) Do not save zonefile')
        print('')

        selection = raw_input('Selection: ').lower()

        if selection == 'd':
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

                print("Bad selection")

        elif selection == 'd':
            # save zonefile
            break

        elif selection == 'e':
            # do not save zonefile 
            return None

        log.debug("zonefile is now:\n{}".format(json.dumps(zonefile, indent=4, sort_keys=True)))

    return zonefile
