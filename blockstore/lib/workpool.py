from multiprocessing import Pool
import threading

from config import DEBUG

import logging
import os
import sys
import signal

log = logging.getLogger()
log.setLevel(logging.DEBUG if DEBUG else logging.INFO)
log_format = ('[%(levelname)s] [%(module)s:%(lineno)d] %(message)s' if DEBUG else '%(message)s')
formatter = logging.Formatter( log_format )

# bitcoind just for this process
process_local_bitcoind = None

# factory method for generating bitcoind connections 
process_local_bitcoind_factory = None

def multiprocess_bitcoind( reset=False ):
   """
   Get a per-process bitcoind client.
   """
   
   global process_local_bitcoind, process_local_bitcoind_factory
   
   if reset: 
      process_local_bitcoind = None 
   
   if process_local_bitcoind is None:
      # this proces does not yet have a bitcoind client.
      # make one.
      if process_local_bitcoind_factory is not None:
         process_local_bitcoind = process_local_bitcoind_factory()
      else:
         raise Exception("No multiprocess bitcoind connection factory is set.  Please call " +
                         "'multiprocess_bitcoind_factory()' with an appropriate callback before " +
                         "trying to access bitcoind in a mulitprocess environment.")
      
   return process_local_bitcoind
   
   
def multiprocess_bitcoind_factory( factory_cb ):
   """
   Set the factory method for generating bitcoind connections.
   Call this before calling multiprocess_bitcoind()
   """
   global process_local_bitcoind_factory
   process_local_bitcoind_factory = factory_cb
