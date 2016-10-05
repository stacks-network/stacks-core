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
    along with Blockstack-client. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import os
import importlib

from proxy import *
from virtualchain import SPVClient
import storage

from config import CONFIG_PATH, get_logger, get_config

log = get_logger()

from wallet import *

# ancillary storage providers
STORAGE_IMPL = None
ANALYTICS_KEY = None


def session(conf=None, config_path=CONFIG_PATH, server_host=None, server_port=None,
            storage_drivers=None, metadata_dir=None, spv_headers_path=None, set_global=False):
    """
    Create a blockstack session:
    * validate the configuration
    * load all storage drivers
    * initialize all storage drivers
    * load an API proxy to blockstack

    conf's fields override specific keyword arguments.

    Returns the API proxy object.
    """

    if not conf and config_path:
        conf = get_config(config_path)

    if conf:
        server_host = server_host or conf['server']
        server_port = server_port or conf['port']
        storage_drivers = storage_drivers or conf['storage_drivers']
        metadata_dir = metadata_dir or conf['metadata']
        spv_headers_path = spv_headers_path or conf['blockchain_headers']

    if not storage_drivers:
        msg = ('No storage driver(s) defined in the config file. '
               'Please set "storage=" to a comma-separated list of drivers')
        log.error(msg)
        sys.exit(1)

    # create proxy
    proxy = BlockstackRPCClient(server_host, server_port)

    # load all storage drivers
    for storage_driver in storage_drivers.split(','):
        storage_impl = load_storage(storage_driver)
        if not storage_impl:
            log.error('Failed to load storage driver "{}"'.format(storage_driver))
            sys.exit(1)

        rc = register_storage(storage_impl, conf)
        if not rc:
            log.error('Failed to initialize storage driver "{}" ({})'.format(storage_driver, rc))
            sys.exit(1)

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
        log.debug('Loaded storage driver "{}"'.format(module_name))
    except ImportError as e:
        msg = ('Failed to import blockstack_client.backend.drivers.{}. '
               'Please verify that it is installed and is accessible via your PYTHONPATH')
        raise Exception(msg.format(module_name))

    return storage_impl


def register_storage(storage_impl, conf):
    """
    Register a storage implementation.
    """
    rc = storage.register_storage(storage_impl)
    if rc:
        rc = storage_impl.storage_init(conf)

    return rc


def get_analytics_key(uuid, proxy=None):
    """
    Get the analytics key from the blockstack server
    """

    key = os.environ.get('BLOCKSTACK_TEST_ANALYTICS_KEY')

    if key:
        return key

    try:
        proxy = proxy or get_default_proxy()
        # TODO: proxy does not have a get_analytics_key function.
        key = proxy.get_analytics_key(uuid)  # BUG:?
    except Exception as e:
        log.debug('Failed to get analytics key')
        return

    key = key or {}
    if 'error' in key:
        log.debug('Failed to fetch analytics key: {}'.format(key['error']))
        return

    key = key.get('analytics_key')
    if key:
        return key

    log.debug('No analytics key returned')

    return


def analytics_event(event_type, event_payload, config_path=CONFIG_PATH,
                    proxy=None, analytics_key=None, action_tag='Perform action'):
    """
    Log an analytics event
    Return True if logged
    Return False if not

    The client uses 'Perform action' as its action tag, so we can distinguish
    client events from server events.  The server uses separate action tags.
    """
    global ANALYTICS_KEY

    try:
        import mixpanel
    except:
        log.debug('mixpanel is not installed; no analytics will be reported')
        return False

    conf = get_config(path=config_path)
    if not conf:
        log.debug('Failed to load config')
        return False

    if not conf['anonymous_statistics']:
        return False

    u = conf['uuid']

    # use the given analytics key, if possible. or fallback.
    analytics_key = analytics_key or ANALYTICS_KEY

    # no fallback. so fetch from server.
    if not analytics_key:
        ANALYTICS_KEY = ANALYTICS_KEY or get_analytics_key(u, proxy=proxy)
        analytics_key = ANALYTICS_KEY

        # all attempts failed. nothing more to do.
        if not analytics_key:
            return False

    # log the event
    log.debug('Track event "{}": {}'.format(event_type, event_payload))
    mp = mixpanel.Mixpanel(analytics_key)
    mp.track(u, event_type, event_payload)
    mp.track(u, action_tag, {})

    return True


def analytics_user_register(u, email, config_path=CONFIG_PATH, proxy=None):
    """
    Register a user with the analytics service
    """
    global ANALYTICS_KEY

    try:
        import mixpanel
    except:
        log.debug('mixpanel is not installed; no analytics will be reported')
        return False

    conf = get_config(path=config_path)
    if not conf:
        log.debug('Failed to load config')
        return False

    if not conf['anonymous_statistics']:
        return False

    ANALYTICS_KEY = ANALYTICS_KEY or get_analytics_key(u)
    if not ANALYTICS_KEY:
        return False

    # register the user
    log.debug('Register user "{}"'.format(u))
    mp = mixpanel.Mixpanel(ANALYTICS_KEY)
    mp.people_set_once(u, {})

    return True


def analytics_user_update(payload, proxy=None):
    """
    Update a user's info on the analytics service
    """
    global ANALYTICS_KEY

    try:
        import mixpanel
    except:
        log.debug('mixpanel is not installed; no analytics will be reported')
        return False

    conf = get_config(config_path)
    if not conf:
        log.debug('Failed to load config')
        return False

    if not conf['anonymous_statistics']:
        return False

    u = conf['uuid']
    ANALYTICS_KEY = ANALYTICS_KEY or get_analytics_key(u)
    if not ANALYTICS_KEY:
        return False

    # update the user
    log.debug('Update user "{}"'.format(u))
    mp = mixpanel.Mixpanel(ANALYTICS_KEY)
    mp.people_append(u, payload)

    return True
