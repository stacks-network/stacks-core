from ..parsing import parse_nameop
from .nulldata import get_nulldata, has_nulldata
import traceback

from ..config import DEBUG, CACHE_ROOT, CACHE_TX_DIR, CACHE_BLOCK_DATA_DIR, CACHE_BLOCK_HASH_DIR, MULTIPROCESS_RPC_RETRY, MULTIPROCESS_WORKER_BATCH, MULTIPROCESS_NUM_WORKERS
from ..workpool import multiprocess_bitcoind

import logging
import os
from ..cache import *

from bitcoinrpc.authproxy import JSONRPCException

log = logging.getLogger()
log.setLevel(logging.DEBUG if DEBUG else logging.INFO)
log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' if DEBUG else '%(message)s')
formatter = logging.Formatter( log_format )


def getrawtransaction( bitcoind, block_hash, txid, verbose=0 ):
   """
   Get a raw transaction by txid, but check our local cache first.
   Only call out to bitcoind if we need to.
   """
   
   exc_to_raise = None
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      try:
         if bitcoind is None:
            # called in multiprocess context
            # get process-local bitcoind 
            bitcoind = multiprocess_bitcoind()
            
         tx = cache_get_tx( block_hash, txid )
         if tx is not None:
            return tx 
         
         # cache miss
         try:
            
            tx = bitcoind.getrawtransaction( txid, verbose )
            
         except JSONRPCException, je:
            log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
            exc_to_raise = je
            continue

         if tx is not None and "txid" in tx.keys():
            cache_put_tx( block_hash, txid, tx )
            
         return tx 
      
      except Exception, e:
         log.exception(e)
         exc_to_raise = e 
         continue

   if exc_to_raise is not None:
      # tried as many times as we dared, so bail 
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)


def getrawtransaction_async( workpool, block_hash, tx_hash, verbose ):
   """
   Get a block transaction, asynchronously, using the pool of processes
   to go get it.
   """
   
   tx_result = workpool.apply_async( getrawtransaction, (None, block_hash, tx_hash, verbose) )
   return tx_result


def getblockhash( bitcoind, block_number ):
   """
   Get a block's hash, given its ID.
   Check the local cache first, then ask bitcoind.
   """
   
   exc_to_raise = None  # exception to raise if we fail

   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      try:
            
         if bitcoind is None:
            # multiprocess context 
            bitcoind = multiprocess_bitcoind()
            
         block_hash = cache_get_block_hash( block_number )
         
         if block_hash is not None:
            return block_hash 
         
         block_hash = None
         try:
         
            block_hash = bitcoind.getblockhash( block_number )
         except JSONRPCException, je:
            log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
            exc_to_raise = je 
            continue
         
         if block_hash is not None:
            # should never be None....
            cache_put_block_hash( block_number, block_hash )
            
         return block_hash
      
      except Exception, e:
         log.exception(e)
         exc_to_raise = e
         continue
   
   if exc_to_raise is not None:
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)
   

def getblockhash_async( workpool, block_number ):
   """
   Get a block's hash, asynchronously, given its ID
   Return a future to the block hash 
   """
   
   block_hash_future = workpool.apply_async( getblockhash, (None, block_number) )
   return block_hash_future


def getblock( bitcoind, block_hash ):
   """
   Get a block's data, given its hash.
   Check our cache first.
   """
   
   exc_to_raise = None
   
   for i in xrange(0, MULTIPROCESS_RPC_RETRY):
      try:
         if bitcoind is None:
            # multiprocess context 
            bitcoind = multiprocess_bitcoind()   
         
         block_data = cache_get_block_data( block_hash )
         if block_data is not None:
            return block_data 
         
         block_data = None 
         try:
            
            block_data = bitcoind.getblock( block_hash )
         except JSONRPCException, je:
            log.error("\n\n[%s] Caught JSONRPCException from bitcoind: %s\n" % (os.getpid(), repr(je.error)))
            exc_to_raise = je
            continue
         
         if block_data is not None:
            # should never be None....
            cache_put_block_data( block_hash, block_data )
         
         return block_data 
      
      except Exception, e:
         log.exception(e)
         exc_to_raise = e
         continue
      
   if exc_to_raise is not None:
      raise exc_to_raise
   
   else:
      raise Exception("Failed after %s attempts" % MULTIPROCESS_RPC_RETRY)
   


def getblock_async( workpool, block_hash ):
   """
   Get a block's data, given its hash.
   Return a future to the data.
   """
   block_future = workpool.apply_async( getblock, (None, block_hash) )
   return block_future 


def get_sender_and_amount_in_from_txn( tx, output_index ):

   # grab the previous tx output (the current input)
   try:
      prev_tx_output = tx['vout'][output_index]
   except Exception, e:
      print "output_index = '%s'" % output_index
      raise e

   # make sure the previous tx output is valid
   if not ('scriptPubKey' in prev_tx_output and 'value' in prev_tx_output):
      return (None, None)

   # extract the script pubkey
   script_pubkey = prev_tx_output['scriptPubKey']
   # build and append the sender to the list of senders
   amount_in = int(prev_tx_output['value']*10**8)
   sender = {
         "script_pubkey": script_pubkey.get('hex'),
         "amount": amount_in,
         "addresses": script_pubkey.get('addresses')
   }
   
   return sender, amount_in


def get_senders_and_total_in( bitcoind, block_hash, inputs ):
        
   senders = []
   total_in = 0
      
   # analyze the inputs for the senders and the total amount in
   for input in inputs:
      # make sure the input is valid
      if not ('txid' in input and 'vout' in input):
         continue

      # get the tx data for the specified input
      tx_hash = input['txid']
      tx_output_index = input['vout']
      
      # log.debug("getrawtransaction( '%s', 1 )" % tx_hash )
      
      tx = getrawtransaction( bitcoind, block_hash, tx_hash, 1 )
      
      # make sure the tx is valid
      if not ('vout' in tx and tx_output_index < len(tx['vout'])):
         continue

      sender, amount_in = get_sender_and_amount_in_from_txn( tx, tx_output_index )
      if sender is None or amount_in is None:
         continue
      
      senders.append(sender)
      # increment the total amount going in to the transaction
      total_in += amount_in

   # return the senders and the total in
   return senders, total_in


def get_total_out(outputs):
    total_out = 0
    # analyze the outputs for the total amount out
    for output in outputs:
        amount_out = int(output['value']*10**8)
        total_out += amount_out
    return total_out


def process_nulldata_tx( bitcoind, block_hash, tx ):
    if not ('vin' in tx and 'vout' in tx and 'txid' in tx):
        return None

    inputs, outputs, txid = tx['vin'], tx['vout'], tx['txid']
    senders, total_in = get_senders_and_total_in(bitcoind, block_hash, inputs )
    total_out = get_total_out( outputs )
    nulldata = get_nulldata(tx)

    # extend the tx
    tx['nulldata'] = nulldata
    tx['senders'] = senders
    tx['fee'] = total_in - total_out
    # print tx['fee']

    return tx


def process_nulldata_tx_async( workpool, block_hash, tx ):
    
    """
    Returns: [(input_idx, tx_fut, tx_output_index)]
    """
    tx_futs = []
    senders = []
    total_in = 0
    
    if not ('vin' in tx and 'vout' in tx and 'txid' in tx):
        return None

    inputs = tx['vin']
    
    # TODO : preserve ordering of senders relative to inputs
    for i in xrange(0, len(inputs)):
      input = inputs[i]
      
      # make sure the input is valid
      if not ('txid' in input and 'vout' in input):
         continue
      
      # get the tx data for the specified input
      tx_hash = input['txid']
      tx_output_index = input['vout']
      
      tx_fut = getrawtransaction_async( workpool, block_hash, tx_hash, 1 )
      tx_futs.append( (i, tx_fut, tx_output_index) )
    
    return tx_futs 


def future_next( fut_records, fut_inspector ):
   
   """
   Find and return a record in a list of records, whose 
   contained future (obtained by the callable fut_inspector)
   is ready and has data to be gathered.
   
   If no such record exists, then select one and block on it
   until its future has data.
   """
   
   if len(fut_records) == 0:
      return None 
   
   for fut_record in fut_records:
      fut = fut_inspector( fut_record )
      if fut is not None:
         if fut.ready():
            fut_records.remove( fut_record )
            return fut_record 
      
   # no ready futures.  wait for one 
   for fut_record in fut_records:
      fut = fut_inspector( fut_record )
      if fut is not None:
         
         # NOTE: interruptable
         fut.wait( 10000000000000000L )
         
         fut_records.remove( fut_record )
         return fut_record
   

def get_nulldata_txs_in_blocks( workpool, blocks ):
   
   """
   Obtain the nulldata transactions for a collection of blocks.
   Farm out the requisite RPCs to a workpool of processes, each 
   of which have their own bitcoind RPC client.
   
   Returns [(block_number, [txs])]
   """
   
   nulldata_tx_map = {}    # {block_number: [(tx_hash, tx)]}
   nulldata_txs = []
   
   # break work up into slices so we don't run out of memory 
   slice_len = MULTIPROCESS_WORKER_BATCH * MULTIPROCESS_NUM_WORKERS
   slice_count = 0
   
   while slice_count * slice_len < len(blocks):
      
      block_hash_futures = []
      block_data_futures = []
      tx_futures = []
      nulldata_tx_futures = []
      all_nulldata_tx_futures = []
      
      block_slice = blocks[ (slice_count * slice_len) : min((slice_count+1) * slice_len, len(blocks)-1) ]
      
      # get all block hashes 
      for block_number in block_slice:
         block_hash_fut = getblockhash_async( workpool, block_number )
         block_hash_futures.append( (block_number, block_hash_fut) )
      
      # coalesce all block hashes, and start getting each block's data
      for i in xrange(0, len(block_hash_futures)):
         
         block_number, block_hash_fut = future_next( block_hash_futures, lambda f: f[1] )
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         block_hash = block_hash_fut.get( 10000000000000000L )
         block_data_fut = getblock_async( workpool, block_hash )
         block_data_futures.append( (block_number, block_hash, block_data_fut) )
      
      # coalesce block data, and get tx hashes 
      for i in xrange(0, len(block_data_futures)):
         
         block_number, block_hash, block_data_fut = future_next( block_data_futures, lambda f: f[2] )
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         block_data = block_data_fut.get( 10000000000000000L )
         
         if 'tx' not in block_data:
            log.error("tx not in block data of %s" % block_number)
            return nulldata_txs
         
         tx_hashes = block_data['tx']

         log.debug("Get %s transactions from block %d" % (len(tx_hashes), block_number))
         
         # can get transactions asynchronously with a workpool
         # NOTE: tx order matters! remember the order we saw them in
         for j in xrange(0, len(tx_hashes)):
            
            tx_hash = tx_hashes[j]
            
            # dispatch all transaction queries for this block
            tx_fut = getrawtransaction_async( workpool, block_hash, tx_hash, 1 )
            tx_futures.append( (block_number, j, block_hash, tx_fut) )
            
            
      # coalesce raw transaction queries...
      for i in xrange(0, len(tx_futures)):
         
         block_number, tx_index, block_hash, tx_fut = future_next( tx_futures, lambda f: f[3] )
         
         # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
         tx = tx_fut.get( 10000000000000000L )
         
         if tx and has_nulldata(tx):
            
            # go get these transactions, but tag each future with the hash of the parent tx
            nulldata_tx_futs_and_output_idxs = process_nulldata_tx_async( workpool, block_hash, tx )
            if nulldata_tx_futs_and_output_idxs is not None:
               nulldata_tx_futures.append( (block_number, tx_index, tx, nulldata_tx_futs_and_output_idxs) )
            
            
      # coalesce nulldata transaction queries...
      for (block_number, tx_index, tx, nulldata_tx_futs_and_output_idxs) in nulldata_tx_futures:
         
         if ('vin' not in tx) or ('vout' not in tx) or ('txid' not in tx):
            continue 
         
         outputs = tx['vout']
         
         total_in = 0
         senders = []
         ordered_senders = []
         
         # gather this tx's nulldata queries
         for i in xrange(0, len(nulldata_tx_futs_and_output_idxs)):
            
            input_idx, nulldata_tx_fut, tx_output_index = future_next( nulldata_tx_futs_and_output_idxs, lambda f: f[1] )
            
            # NOTE: interruptable blocking get(), but should not block since future_next found one that's ready
            nulldata_tx = nulldata_tx_fut.get( 10000000000000000L )
            sender, amount_in = get_sender_and_amount_in_from_txn( nulldata_tx, tx_output_index )
            
            if sender is None or amount_in is None:
               continue
            
            total_in += amount_in 
            
            # NOTE: senders isn't commutative--will need to preserve order
            ordered_senders.append( (input_idx, sender) )
         
         ordered_senders.sort()         # sort on input_idx 
         senders = [sender for (_, sender) in ordered_senders]
         
         total_out = get_total_out( outputs )
         nulldata = get_nulldata( tx )
      
         # extend tx 
         tx['nulldata'] = nulldata
         tx['senders'] = senders
         tx['fee'] = total_in - total_out
         
         if not nulldata_tx_map.has_key( block_number ):
            nulldata_tx_map[ block_number ] = [(tx_index, tx)]
         else:
            nulldata_tx_map[ block_number ].append( (tx_index, tx) )
   
      # next slice
      slice_count += 1
   
   # convert {block_number: [tx]} to [(block_number, [tx])] where [tx] is ordered by the order in which the transactions occurred in the block
   for block_number in blocks:
      
      txs = []
      
      if block_number in nulldata_tx_map.keys():
         tx_list = nulldata_tx_map[ block_number ]     # [(tx_index, tx)]
         tx_list.sort()                                # sorts on tx_index--preserves order in the block
         
         txs = [ tx for (_, tx) in tx_list ]
         
      nulldata_txs.append( (block_number, txs) )
      
   return nulldata_txs


def get_nulldata_txs_in_block(bitcoind, block_number ):
    nulldata_txs = []

    block_hash = getblockhash( bitcoind, block_number )
    block_data = getblock( bitcoind, block_hash )

    if 'tx' not in block_data:
      return nulldata_txs

    tx_hashes = block_data['tx']
    
    log.debug("Get %s transactions from block %d" % (len(tx_hashes), block_number))
    
    # have to get them all synchronously
    for tx_hash in tx_hashes:
      tx = get_tx(bitcoind, tx_hash)
      if tx and has_nulldata(tx):
         nulldata_tx = process_nulldata_tx(bitcoind, tx)
         if nulldata_tx:
            nulldata_txs.append(nulldata_tx)
            
    return nulldata_txs
