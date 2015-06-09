
from config import CACHE_ROOT, CACHE_BLOCK_ID_DIR, CACHE_ENABLE, CACHE_BUFLEN

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
   
   try:
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
   
   except Exception, e:
      log.exception(e)
      return None
   
   return obj
   

def cache_get_size( path ):
   """
   Get the size of a cached file.
   Return None if not cached
   """
   
   if not os.path.exists( path ):
      return None 
   
   if not os.path.isfile( path ):
      return None
   
   return os.stat( path ).st_size
   

def cache_put_impl( path, obj ):
   """
   Pickle and write an object to the given path.
   Return the serialized length on success
   Return None on error
   """
   
   try:
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
            
         return len(pstr)
      
   except Exception, e:
      log.exception(e)
      return None
   
   
   
def cache_put( path, obj, async=True ):
   """
   Put something into the cache--either synchronously, or asynchronously.
   If synchronously, return the length of the object put.
   Otherwise, return None
   """
   
   global cache_thread
   
   if not CACHE_ENABLE:
      return
   
   if async:
      if cache_thread is None:
         cache_start()
   
      cache_thread.queue( path, obj )
      return None
      
   else:
      return cache_put_impl( path, obj )
      

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
      

def cache_block_id_path( block_id ):
   """
   Path to a ched block, by id 
   """
   root = CACHE_BLOCK_ID_DIR
   path = os.path.join( root, str(block_id) )
   return path
   

def cache_get_block( block_id ):
   """
   Get a block by ID 
   """
   data_path = cache_block_id_path( block_id )
   return cache_get( data_path )


def cache_get_block_size( block_data ):
   """
   Find out out big a block will be when cached.
   """
   pstr = None
   try:
      pstr = pickle.dumps( block_data )
      return len(pstr)
   except pickle.PickleError, pe:
      # NOTE: Debug-level since this is potentially sensitive information
      log.debug("Failed to pickle")
      return None


def cache_put_block( block_id, block_data ):
   """
   Put a block by ID 
   """
   data_path = cache_block_id_path( block_id )
   return cache_put( data_path, block_data );
