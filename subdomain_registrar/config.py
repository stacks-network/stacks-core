#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-client
    ~~~~~
    copyright: (c) 2017 by Blockstack.org

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

import os, ConfigParser
from blockstack_client import config as blockstack_client_config

SUBDOMAIN_NAME_PATTERN = r'([a-z0-9\-_+]{{{},{}}})$'.format(3, 36)

config = None
homedir = None
def __get_homedir():
    global homedir
    __get_or_load_config() # note: I'm depending on global side-effect of loading config
    return homedir

def __get_or_load_config():
    global config, homedir
    if config and homedir:
        return dict(config.items("registrar-config"))

    filename = os.environ.get(
        "BLOCKSTACK_SUBDOMAIN_CONFIG", 
        os.path.expanduser("~/.blockstack_subdomains/config.ini"))
    homedir = os.path.dirname(filename)
    if not os.path.exists(homedir):
        os.makedirs(homedir)
    if not os.path.exists(filename):
        newconfig = ConfigParser.ConfigParser()
        subdomain_defaults = {
            "bind_address" : "localhost",
            "bind_port" : "7103",
            "transaction_frequency" : str(15*60),
            "maximum_entries_per_zonefile" : "100",
            "core_auth_token" : "False",
            "core_config" : "~/.blockstack/client.ini",
            "core_endpoint" : "http://localhost:6270",
        }
        newconfig.add_section("registrar-config")
        for k,v in subdomain_defaults.items():
            newconfig.set("registrar-config", k, v)
        with open(filename, 'w') as configout:
            newconfig.write(configout)

    config = ConfigParser.ConfigParser()
    config.read(filename)
    return dict(config.items("registrar-config"))

def get_core_auth():
    c = __get_or_load_config()
    configured_auth_token = c.get("core_auth_token", "False")
    if configured_auth_token.lower() != "false":
        return c.get("core_auth_token")
    DEFAULT_CONFIG_FILE = os.environ.get(
        "BLOCKSTACK_CLIENT_CONFIG", "~/.blockstack/client.ini")
    config_file = os.path.expanduser(c.get("core_config", DEFAULT_CONFIG_FILE)) 
    auth = blockstack_client_config.get_config(config_file)['api_password']
    assert auth
    return auth

def get_core_api_endpoint():
    c = __get_or_load_config()
    endpoint = c.get("core_endpoint", 'http://localhost:6270')
    return endpoint, get_core_auth()

def get_tx_frequency():
    """ Returns transaction frequency of subdomain registrations in seconds """
    c = __get_or_load_config()
    return int(c.get("transaction_frequency", 15*60))

def max_entries_per_zonefile():
    """ Maximum entries you will try to pack in a zonefile, actual maximum may be lower
        since zonefiles can only store 4kb data """
    c = __get_or_load_config()
    return int(c.get("maximum_entries_per_zonefile", 100))

def get_logfile():
    homedir =  __get_homedir()
    path = os.path.expanduser("{}/subdomain_registrar.log".format(homedir))
    return path

def get_subdomain_registrar_db_path():
    homedir =  __get_homedir()
    return os.path.expanduser("{}/registrar.db".format(homedir))

def get_lockfile():
    homedir =  __get_homedir()
    return os.path.expanduser("{}/registrar.pid".format(homedir))

def get_api_bind_address():
    c = __get_or_load_config()
    return c.get("bind_address", "localhost")

def get_api_bind_port():
    c = __get_or_load_config()
    return int(c.get("bind_port", "7103"))
