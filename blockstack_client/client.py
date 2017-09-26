#!/usr/bin/env python2
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
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os
import importlib

from proxy import BlockstackRPCClient, set_default_proxy, get_default_proxy
from virtualchain import SPVClient
import storage

from .constants import CONFIG_PATH, VERSION
from .config import get_config, semver_match
from .logger import get_logger

log = get_logger()

# ancillary storage providers
STORAGE_IMPL = None

def session(conf=None, config_path=CONFIG_PATH, server_host=None, server_port=None,
            wallet_password=None, storage_drivers=None, metadata_dir=None,
            spv_headers_path=None, set_global=False, server_protocol = None):
    """
    Create a blockstack session:
    * validate the configuration
    * load all storage drivers
    * initialize all storage drivers
    * load an API proxy to blockstack

    conf's fields override specific keyword arguments.

    Returns the API proxy object.
    """

    if set_global:
        if server_host is not None:
            os.environ['BLOCKSTACK_CLI_SERVER_HOST'] = server_host

        if server_port is not None:
            os.environ['BLOCKSTACK_CLI_SERVER_PORT'] = str(server_port)

    if conf is None:
        conf = get_config(config_path)
        if conf is None:
            log.error("Failed to read configuration file {}".format(config_path))
            return None

        conf_version = conf.get('client_version', '')
        if not semver_match(conf_version, VERSION):
            log.error("Failed to use legacy configuration file {}".format(config_path))
            return None

    if conf is not None:
        if server_host is None:
            server_host = conf['server']
        if server_port is None:
            server_port = conf['port']
        if server_protocol is None:
            server_protocol = conf['protocol']
        if storage_drivers is None:
            storage_drivers = conf['storage_drivers']
        if metadata_dir is None:
            metadata_dir = conf['metadata']
        if spv_headers_path is None:
            spv_headers_path = conf['bitcoind_spv_path']

    if storage_drivers is None:
        msg = ('No storage driver(s) defined in the config file. '
               'Please set "storage=" to a comma-separated list of drivers')
        log.error(msg)
        sys.exit(1)

    # create proxy
    log.debug('Connect to {}://{}:{}'.format(server_protocol, server_host, server_port))
    proxy = BlockstackRPCClient(server_host, server_port, protocol = server_protocol)

    # load all storage drivers
    loaded = []
    for storage_driver in storage_drivers.split(','):
        storage_impl = load_storage(storage_driver)
        if storage_impl is None:
            log.error('Failed to load storage driver "{}"'.format(storage_driver))
            sys.exit(1)
        loaded.append(storage_driver)
        rc = register_storage(storage_impl, conf)
        if not rc:
            log.error('Failed to initialize storage driver "{}" ({})'.format(storage_driver, rc))
            sys.exit(1)
    log.debug('Loaded storage drivers {}'.format(loaded))
    # initialize SPV
    SPVClient.init(spv_headers_path)
    proxy.spv_headers_path = spv_headers_path
    proxy.conf = conf

    if set_global:
        set_default_proxy(proxy)

    return proxy


def load_storage(module_name):
    """
    Load a storage implementation, given its module name.
    """
    try:
        prefix = 'blockstack_client.backend.drivers.{}'
        storage_impl = importlib.import_module(prefix.format(module_name))
        storage_impl.__name__ = module_name
    except ImportError as e:
        msg = ('Failed to import blockstack_client.backend.drivers.{}. '
               'Please verify that it is installed and is accessible via your PYTHONPATH')
        log.exception(e)
        raise Exception(msg.format(module_name))

    return storage_impl


def register_storage(storage_impl, conf, **driver_kw):
    """
    Register a storage implementation.
    """
    rc = storage.register_storage(storage_impl)
    if rc:
        rc = storage_impl.storage_init(conf, **driver_kw)

    return rc


