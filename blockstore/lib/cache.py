
from config import CACHE_ROOT, CACHE_TX_DIR, CACHE_BLOCK_HASH_DIR, CACHE_BLOCK_DATA_DIR, CACHE_ENABLE, CACHE_BUFLEN

import os 
import pickle
import threading
import collections
import logging
import errno
from config import DEBUG

log = logging.getLogger()
log.setLevel(logging.DEBUG if DEBUG else logging.INFO)
log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' if DEBUG else '%(message)s')
formatter = logging.Formatter( log_format )


# process-local cache writer thread
cache_thread = None

class cache_writer( threading.Thread ):
   
   def __init__(self, limit ):
      
      super( cache_writer, self ).__init__()
      self.sem = threading.Semaphore(limit)
      self.work_sem = threading.Semaphore(0)
      self.workqueue = collections.deque()
      self.running = False
      self.limit = limit
      
   def start( self ):
      self.running = True
      log.debug("[%s] Cache thread started" % (os.getpid()))
      super( cache_writer, self ).start()
      
   
   def cancel( self ):
      if self.running:
         self.running = False 
         self.work_sem.release()
      
   def queue( self, path, obj ):
      
      if len(self.workqueue) >= self.limit:
         log.debug("[%s] Cache limit reached" % (os.getpid()))
         
      self.sem.acquire()
      self.workqueue.append( (path, obj) )
      self.work_sem.release()
      
   def run(self):
      
      while self.running:
         
         # wait for work 
         self.work_sem.acquire()
         if not self.running:
            break
         
         path, obj = self.workqueue.popleft()
         
         cache_put_impl( path, obj )
         
         # have a slot 
         self.sem.release()
      
      log.debug("[%s] Cache thread stopped" % (os.getpid()))
      

def cache_get( path ):
   """
   Read and unpickle a Python object at the given path.
   """
   
   obj = None 
   if not CACHE_ENABLE:
      return None
   
   if os.path.exists( path ):
      
      fd = None
      pstr = None
      
      with open(path, "r") as fd:
         pstr = fd.read()
         
         try:
            obj = pickle.loads( pstr )
            
         except pickle.PickleError, pe:
            log.debug("Failed to unpickle %s" % path)
            obj = None
         
   return obj
   

def cache_put_impl( path, obj ):
   """
   Pickle and write an object to the given path.
   """
   
   if not os.path.exists( os.path.dirname( path ) ):
      try:
         os.makedirs( os.path.dirname( path ) )
      except OSError, oe:
         if oe.errno == errno.EEXIST:
            pass 
         else:
            raise
   
   pstr = None
   try:
      pstr = pickle.dumps( obj )
   except pickle.PickleError, pe:
      # NOTE: Debug-level since this is potentially sensitive information
      log.debug("Failed to pickle %s" % repr(obj))
      pstr = None
   
   if pstr is not None:
      # save 
      
      with open(path, "w") as fd:
         fd.write( pstr )
   
   
def cache_put( path, obj, async=True ):
   """
   Put something into the cache--either synchronously, or asynchronously.
   """
   
   global cache_thread
   
   if not CACHE_ENABLE:
      return
   
   if async:
      if cache_thread is None:
         cache_start()
   
      cache_thread.queue( path, obj )
      
   else:
      cache_put_impl( path, obj )
      

def cache_start():
   """
   Start processing cache requests 
   """
   global cache_thread 
   if cache_thread is None:
      cache_thread = cache_writer( CACHE_BUFLEN )
   
   if not cache_thread.running:
      cache_thread.start()
   

def cache_stop():
   """
   Abruptly stop processing cache requests 
   """
   global cache_thread
   
   if cache_thread is not None:
      cache_thread.cancel()
      

def cache_tx_path( block_hash, txid ):
   """
   Generate the path to a cached transaction.
   """
   root = CACHE_TX_DIR 
   path = os.path.join( root, block_hash, txid )
   return path


def cache_get_tx( block_hash, txid ):
   """
   Get a cached transaction, from the txid.
   Return None if not cached.
   """
   tx_path = cache_tx_path( block_hash, txid )
   return cache_get( tx_path )


def cache_put_tx( block_hash, txid, tx ):
   """
   Cache a transaction, given its tx ID and the tx data.
   """
   
   if tx is not None and "txid" in tx.keys():
      tx_path = cache_tx_path( block_hash, txid )
      return cache_put( tx_path, tx )
            
   else:
      raise Exception("'txid' not in transaction")
   
   
def cache_block_hash_path( block_id ):
   """
   Generate the path to a cached block hash.
   Convert to hex and separate every four characters with /
   """
   root = CACHE_BLOCK_HASH_DIR
   path = os.path.join( root, str(block_id) )
   return path

   
def cache_get_block_hash( block_id ):
   """
   Get a cached block hash.
   Return None if not present.
   """
   
   bhash_path = cache_block_hash_path( block_id )
   return cache_get( bhash_path )


def cache_put_block_hash( block_id, bhash ):
   """
   Put a block hash
   """
   bhash_path = cache_block_hash_path( block_id )
   return cache_put( bhash_path, bhash )


def cache_block_data_path( block_hash ):
   """
   Generate the path to cached block data, given its hash.
   """
   root = CACHE_BLOCK_DATA_DIR
   path = os.path.join( root, block_hash )
   return path 


def cache_get_block_data( block_hash ):
   """
   Get a block's cached data from its hash.
   Return None if not cached locally.
   """
   data_path = cache_block_data_path( block_hash )
   return cache_get( data_path )


def cache_put_block_data( block_hash, block_data ):
   """
   Put a block's data to the cache.
   """
   data_path = cache_block_data_path( block_hash )
   return cache_put( data_path, block_data )
