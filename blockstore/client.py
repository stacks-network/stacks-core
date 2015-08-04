#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore
    ~~~~~
    :copyright: (c) 2015 by Openname.org
    :license: MIT, see LICENSE for more details.
"""

import argparse
import sys
import json
import traceback
import types 

from lib import config, schemas, parsing, profile
import pybitcoin

import logging

from twisted.python import log
from twisted.internet.error import ConnectionRefusedError
from twisted.internet import reactor
from txjsonrpc.netstring.jsonrpc import Proxy

# Disable twisted log messages, because it's too noisy
log.startLoggingWithObserver(log.PythonLoggingObserver, setStdout=0)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)
formatter = logging.Formatter('%(message)s')
console.setFormatter(formatter)
logger.addHandler(logging.NullHandler())
# logger.addHandler(console)

# default API endpoint proxy to blockstored
default_proxy = Proxy(config.BLOCKSTORED_SERVER, config.BLOCKSTORED_PORT)

def printValue(value):
   # logger.info(pretty_dump(value))
   print pretty_dump(value)


def printError(error):
   reply = {}
   traceback.print_exc()
   reply['error'] = "Error"

   if error.type is ConnectionRefusedError:
      reply['error'] = "Failed to connect to Blockstored"

   # logger.info(pretty_dump(reply))
   print pretty_dump(reply)


def shutDown(data):
   reactor.stop()


def link_immutable_profile( user_profile_json, data_hash ):
   """
   Reactor callback to a lookup(name) that 
   puts a hash for immutable data into a user's profile,
   and serializes and returns the new JSON
   """
   
   user_profile = parsing.parse_user_profile( user_profile_json )
   if user_profile is None:
      log.error("Failed to parse user profile '%s'" % user_profile_json )
      raise Exception("Failed to parse user profile")
   
   profile.add_immutable_data( user_profile, data_hash )
   
   # serialize 
   new_profile_json = None 
   try:
      new_profile_json = profile.serialize_user_profile( user_profile )
   except Exception, e:
      log.error("Failed to serialize '%s'" % new_profile_json )
      raise e
   
   return new_profile_json 
   
    
def update_profile_deferred( user_profile_json, apiProxy, name, privatekey ):
   """
   Reactor callback to update() the user profile.
   Returns a deferred call to update().
   """
   
   update_key = pybitcoin.hash.hex_hash160( user_profile_json )
   update_deferred = apiProxy.callRemote("update", name, update_key, privatekey )
   return update_deferred
   
   
def store_profile( result, user_profile_json ):
   """
   Store JSON profile data to the storage providers, synchronously.
   """
   
   profile_key = pybitcoin.hash.hex_hash160( user_profile_json )
   result = dht_server.set(key, value)
   return result       
   

def pretty_dump(input):
   """ pretty dump
   """
   return json.dumps(input, sort_keys=True, indent=4, separators=(',', ': '))


def getinfo( proxy=default_proxy ):
   """
   getinfo
   """
   client = proxy.callRemote('getinfo')
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)


def ping( proxy=default_proxy ):
   """
   ping
   """
   client = proxy.callRemote('ping')
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def lookup( name, proxy=default_proxy ):
   """
   lookup
   """
   client = proxy.callRemote('lookup', str(name))
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)


def preorder( name, privatekey, proxy=default_proxy ):
   """
   preorder
   """
   client = proxy.callRemote( 'preorder', str(name), str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)


def register( name, privatekey, proxy=default_proxy ):
   """
   register
   """
   client = proxy.callRemote( 'register', str(name), str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def update( name, data, privatekey, proxy=default_proxy ):
   """
   update
   """
   client = proxy.callRemote( 'update', str(name), data, str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def transfer( name, address, privatekey, proxy=default_proxy ):
   """
   transfer
   """
   client = proxy.callRemote( 'transfer', str(name), str(address), str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def renew( name, privatekey, proxy=default_proxy ):
   """
   renew
   """
   client = proxy.callRemote( 'renew', str(name), str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def revoke( name, privatekey, proxy=default_proxy ):
   """
   revoke
   """
   # TODO 
   client = proxy.callRemote( 'revoke', str(name), str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def namespace_define( namespace_id, lifetime, base_name_cost, cost_decay_rate, privatekey, proxy=default_proxy ):
   """
   namesapce_define
   """
   client = proxy.callRemote( 'namespace_define', str(namespace_id), int(lifetime), int(base_name_cost), float(cost_decay_rate), str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
def namespace_begin( namespace_id, privatekey, proxy=default_proxy ):
   """
   namespace_begin
   """
   client = proxy.callRemote( 'namespace_begin', str(namespace_id), str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def get_immutable( name, data_key, get_immutable_handlers=None, proxy=default_proxy ):
   """
   get_immutable
   """
   client = proxy.callRemote( 'get_immutable', str(name), str(data_key) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def get_mutable( data_id, name=None, publickey=None, get_mutable_handlers=None, proxy=default_proxy ):
   """
   get_mutable
   """
   # TODO 
   client = proxy.callRemote( 'get_mutable', str(data_id), name, publickey )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def link_immutable( name, data_key, privatekey, proxy=default_proxy ):
   """
   link_immutable
   """
   client = proxy.callRemote( 'link_immutable', str(name), str(data_key), str(privatekey) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)


def has_immutable( name, data_key, proxy=default_proxy ):
   """
   has_immutable
   """
   client = proxy.callRemote( 'has_immutable', str(name), str(data_key) )
   client.addCallback(printValue).addErrback(printError).addBoth(shutDown)
   
   
def put_immutable( name, data, privatekey, put_immutable_handlers=None, proxy=default_proxy ):
   """
   put_immutable
   """
   # TODO 
   pass 


def put_mutable( name, data_id, data, privatekey, proxy=default_proxy ):
   """
   put_mutable
   """
   # TODO 
   pass 


def delete_immutable( name, data_key, privatekey, proxy=default_proxy ):
   """
   delete_immutable
   """
   # TODO 
   pass


def delete_mutable( name, data_id, privatekey, proxy=default_proxy ):
   """
   delete_mutable
   """
   # TODO 
   pass 

