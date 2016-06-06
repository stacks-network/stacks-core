#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack

    Blockstack is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
"""

import logging
import os
import sys
import traceback
import time

import virtualchain
log = virtualchain.get_logger("blockstack-server")

import virtualchain.lib.blockchain.bitcoin as virtualchain_bitcoin
from blockstack_utxo import get_inputs, broadcast_transaction, connect_blockchain_provider

# global config state
blockchain_clients = {}
blockchain_opts = {}
service_opts = {}
blockchain_clients = {}
blockchain_broadcasters = {}

def get_blockchain_client( blockchain_name, new_blockchain_opts=None, new=False ):
   """
   Get or instantiate a blockchain client.
   Optionally re-set the blockchain connection options.
   Return a new proxy object on success.
   Raise on error
   """
   global blockchain_clients
   global blockchain_opts

   if new_blockchain_opts is not None:
       assert new_blockchain_opts.has_key('blockchain')
       assert new_blockchain_opts['blockchain'] == blockchain_name

   if not new and blockchain_clients.has_key(blockchain_name):
      return blockchain_clients[blockchain_name]

   if new or (not blockchain_clients.has_key(blockchain_name) or blockchain_clients[blockchain_name] is None):
      if new_blockchain_opts is not None:
         blockchain_opts[blockchain_name] = new_blockchain_opts
      elif blockchain_opts is not None:
          new_blockchain_opts = copy.deepcopy(blockchain_opts[blockchain_name])

      new_blockchain_client = None
      try:
         if blockchain_opts.has_key('bitcoind_mock') and blockchain_opts['bitcoind_mock']:
            # make a mock connection
            log.debug("Use mock bitcoind")
            import blockstack_integration_tests.mock_bitcoind
            new_blockchain_client = blockstack_integration_tests.mock_bitcoind.connect_mock_bitcoind( blockchain_opts, reset=reset )

         else:
            new_blockchain_client = virtualchain.connect_blockchain( new_blockchain_opts, blockchain=blockchain_name )

         if new:
             return new_blockchain_client

         else:
             # save for subsequent reuse
             blockchain_clients[blockchain_name] = new_blockchain_client
             return new_blockchain_client

      except Exception, e:
         log.exception( e )
         return None


def get_blockchain_opts(blockchain_name):
   """
   Get the blockchain connection arguments for a particular blockchain.
   """

   global blockchain_opts
   return blockchain_opts.get(blockchain_name, None)



def get_service_opts(blockchain_name):
   """
   Get blockchain service provider options for a particular blockchain.
   """
   global service_opts
   return service_opts.get(blockchain_name, None)


def get_blockstack_opts():
   """
   Get blockstack configuration options.
   """
   global blockstack_opts
   return blockstack_opts


def set_blockchain_opts( blockchain_name, new_blockchain_opts ):
   """
   Set new global blockchain operations
   """
   global blockchain_opts
   blockchain_opts[blockchain_name] = new_blockchain_opts


def set_service_opts( blockchain_name, new_service_opts ):
   """
   Set new global blockchain service options
   """
   global service_opts
   service_opts[blockchain_name] = new_service_opts


def set_blockstack_opts( new_opts ):
    """
    Set new global blockstack opts
    """
    global blockstack_opts
    blockstack_opts = new_opts


def blockchain_service_connect(blockchain_name, opts=None ):
   """
   Get or instantiate our blockchain service provider's client.
   Return None if we were unable to connect
   """

   # acquire configuration (which we should already have)
   if opts is None:
       opts = get_service_opts( blockchain_name ) 
       if opts is None:
           opts = get_service_opts( blockchain_name )
           if opts is None:
               _, _, utxo_opts, _, other_blockchain_service_opts = configure( interactive=False, other_blockchains=[blockchain_name] )
               if blockchain_name in other_blockchain_service_opts.keys():
                   opts = other_blockchain_service_opts[blockchain_name]
               else:
                   opts = utxo_opts

   client = None
   if blockchain_name == "bitcoin":
       try:
           client = connect_blockchain_provider( blockchain_name, opts )
           return client 
       except Exception, e:
           log.exception(e)
           return None
       
   else:
       raise NotImplementedError("Don't know how to connect to '%s'" % blockchain_name)


def tx_broadcast_service_connect(blockchain_name, opts=None):
   """
   Get or instantiate our blockchain service provider's transaction broadcaster.
   Fall back to the blockchain provider client, if one is not designated
   """
   
   bstk_opts = get_blockstack_opts()

   # acquire configuration (which we should already have)
   if opts is None or bstk_opts is None:
       cfg_bstk_opts, _, utxo_opts, _, other_blockchain_service_opts = configure( interactive=False, other_blockchains=[blockchain_name] )
       if bstk_opts is None:
           bstk_opts = cfg_bstk_opts

       if opts is None:
           if blockchain_name in other_blockchain_service_opts.keys():
               opts = other_blockchain_service_opts[blockchain_name]
           else:
               opts = utxo_opts 

   # is there a particular blockchain client we want for importing?
   if 'tx_broadcaster' not in blockstack_opts.keys():
       return blockchain_service_connect(blockchain_name, opts=opts)

   try:
       broadcaster = connect_blockchain_provider( blockchain_name, opts )
       return broadcaster 
   except:
       log.exception(e)
       return None 


def get_tx_inputs( blockchain_name, private_key, public_key=None, address=None ):
    """
    Create a transaction for a particular blockchain.
    * look up any input state the transaction needs
    * encode the given transaction state changes (outputs)
    * if private_key is given, sign the transaction with it

    Return the serialized (possibly signed) transaction
    """

    assert public_key is not None or private_key is not None or address is not None, "Need either a public or private key"

    blockchain_client = get_blockchain_client( blockchain_name )
    blockchain_mod = virtualchain.import_blockchain( blockchain_name )

    from_address = None
    pubk = None 

    if public_key is not None:
        # subsidizing 
        pubk = ECPublicKey( public_key )
        from_address = pubk.address()

    elif private_key is not None:
        # ordering directly 
        pubk = ECPrivateKey( private_key ).public_key()
        from_address = pubk.address()
    
    else:
        from_address = address

    inputs = get_inputs( from_address, blockchain_client )

    return inputs


def make_transaction( blockchain_name, inputs, outputs, private_key ):
    """
    Make a (possibly-)signed transaction from state inputs and state outputs,
    destined for a particular blockchain 
    """
    blockchain_mod = virtualchain.import_blockchain( blockchain_name )
    tx_str = None

    if private_key is not None:
        tx_str = blockchain_mod.tx_serialize_sign( inputs, outputs, private_key )
    else:
        tx_str = blockchain_mod.tx_serialize( inputs, outputs )

    return tx_str


def send_transaction( blockchain_name, inputs, outputs, private_key, tx_str=None ):
    """
    Given a signed serialized transaction, send it to the particular
    blockchain.

    Return {'transaction_hash': ...} on success
    Return {'error': ...} on failure
    """

    assert (inputs is not None and outputs is not None) or tx_str is not None, "invalid arguments"

    if tx_str is None:
        tx_str = make_transaction( blockchain_name, inputs, outputs, private_key )

    blockchain_broadcaster = get_tx_broadcaster( blockchain_name )
    response = broadcast_transaction( tx_str, blockchain_broadcaster )
    return response


def send_raw_transaction( blockchain_name, tx_str ):
    """
    Send an already-signed/serialized transaction
    """
    return send_transaction( blockchain_name, None, None, None, tx_str=tx_str )


def make_subsidization_output( payer_inputs, payer_address, op_fee, dust_fee ):
    """
    Given the set of inputs for both the client and payer, as well as the client's 
    desired tx outputs, generate the inputs and outputs that will cause the payer to pay 
    the operation's fees and dust fees.
    
    The client should send its own address as an input, with the same amount of BTC as the output.
    
    Return the payer output to include in the transaction on success, which should pay for the operation's
    fee and dust.
    """

    return {
        "script_hex": virtualchain_bitcoin.make_pay_to_address_script( payer_address ),
        "value": virtualchain_bitcoin.calculate_change_amount( payer_utxo_inputs, op_fee, dust_fee )
    }
    
    
def subsidize_state_transition( blockchain_name, inputs, outputs, fee_cb, max_fee, subsidy_key ):
    """
    Subsidize a state transition with a different key.
    * Add subsidization inputs/outputs
    * Make sure the subsidy does not exceed the maximum subsidy fee
    """

    payer_inputs = get_tx_inputs( blockchain_name, subsidy_key )
    payer_address = ECPrivateKey( subsidy_key ).public_key().address()
   
    # what's the fee?  does it exceed the subsidy?
    dust_fee, op_fee = fee_cb( inputs, outputs )
    if dust_fee is None or op_fee is None:
        log.error("Invalid fee structure")
        return None 
    
    if dust_fee + op_fee > max_fee:
        log.error("Op fee (%s) + dust fee (%s) exceeds maximum subsidy %s" % (dust_fee, op_fee, max_fee))
        return None
    
    else:
        log.debug("%s will subsidize %s satoshi" % (ECPrivateKey( subsidy_key ).public_key().address(), dust_fee + op_fee ))
    
    subsidy_output = make_subsidization_output( payer_inputs, payer_address, op_fee, dust_fee )
    inputs += payer_inputs
    outputs.append( subsidy_output )

    return inputs, outputs
    

