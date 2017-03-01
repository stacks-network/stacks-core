#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org

    This file is part of Blockstack.

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

"""
This is a skeleton no-op driver, meant for tutorial purposes.
It will be dynamically imported by blockstack.

Background
==========

Blockstack storage drivers are responsible for implementing
a get/put/delete interface for two logical types of I/O:
mutable data, and immutable data.

Mutable data is data that does NOT touch the underlying blockchain.
Instead, mutable data is signed by a private key derived from
the keypair listed in the user's zone file.  Most user data
(profiles, application data stores) follows the mutable data
I/O model, since mutable I/O can happen as fast as the storage
service allows.

Immutable data is data that touches the underlying blockchain.
Each 'put' and 'delete' corresponds to an on-chain transaction
(specificially, a NAME_UPDATE transaction that modifies the user's
zone file).  Similarly, each 'get' corresponds to a previously-sent
transaction.  Immutable data is appropriate for storing data that
will only be written once, where freshness, integrity, and consistency
are more important than I/O performance (examples include storing
PGP keys, software releases, and certificates).

In practice, most storage drivers can implement the mutable I/O
path and immutable I/O path the same way; the only difference
between the two will be the interfaces.  For example, the `disk`
driver simply stores everything to disk, immutable or mutable.

Replication Strategy
====================

Replication in Blockstack is best-effort.  On a given `put`, some data may
be successfully replicated to some storage providers, and some data may not.
Blockstack automatically masks any inconsistencies that get introduced
(see Responsibilities below).

Blockstack uses three configuration fields in its config file to
determine how to replicate data.

    * blockstack-client.storage_drivers.  This is the list of storage drivers
    to use to both read and write data.  All of these drivers will be attempted
    on any `get` or `put`.  A `get` or `put` is attempted on each driver in the 
    order they are listed (but this may change in the future).

    * blockstack-client.storage_drivers_required_write.  This is the list of
    storage drivers that must successfully `put` data in order for a write
    to succeed.  If even one of them fails, the entire write fails.

    * blockstack-client.storage_drivers_local.  This is the list of drivers that
    keep their data invisible to other clients.  For example, the `disk` driver
    is listed here by default since writes to disk are invisible to other clients.

In order for `put` to work on mutable data, there must be at least one driver listed in
blockstack-client.storage_drivers_required_write that is NOT listed
blockstack-client.storage_drivers_local.

There are no long-term plans for creating more sophisticated replication strategies.  This
is because more sophisticated strategies can be implemented as "meta drivers" that load
existing drivers as modules, and forward `get` and `put` requests to them according to the
desired strategy.

Responsibilities
================

Blockstack handles a lot of higher-level storage responsibilities on its
own, so the driver implementer can focus on interfacing with the storage
provider and/or creating the desired replication strategy.  The responsibilities
are divided as follows:

    * Consistency.  Blockstack takes care of writing immutable data
    hashes to the zone file, and takes care of maintaining consistency info
    for mutable data.  Specifically:
    
        * Blockstack guarantees per-key monotonic read consistency
        for mutable data (i.e. a `get` on a key returns the same or newer data as
        the previous `get` on the same key, but does not guarantee that the `get` returns
        the same data written by the last `put` on it).
        
        * A correct driver must guarantee per-key read-your-writes
        consistency (i.e. a `put` followed by a `get` on the same key 
        should return the last-`put` data to the local client).
        
        * It is acceptable to rely on the storage system to enforce consistency.
        For example, most cloud storage providers claim to offer per-key sequential
        consistency already (i.e. a `put` followed by a `get` on the same key returns the
        data stored by the `put` to all clients).  However, the driver must mask
        weak consistency by the storage provider if the provider cannot offer per-key
        read-your-writes consistency.
    
    * Authenticity.  Blockstack signs all data before giving it to
    the driver.  The driver does not need to implement separate
    authenticity checks.

    * Integrity.  Similarly, Blockstack ensures that the data hasn't
    been tampered with.  No action is required by the driver.

    * Data Confidentiality.  Blockstack encrypts data before giving it to
    the driver, and decrypts it after it loads it.  However, Blockstack
    does not guarantee that all the data it writes will be encrypted
    (i.e. the user or application may specify that it is "public" data).
    If this is unacceptable, then the driver may take its own additional
    steps to ensure data confidentiality.

    * Behavioral Confidentiality.  Blockstack does NOT take any action to
    hide network-visible access patterns.  Without assistance from the driver,
    someone watching the network can do timing analysis on the packets
    Blockstack sends and receives, and deduce things like the user's network
    location and the application being used.  If behavior confidentiality is
    required, then the driver must take additional steps to implement it.
"""


# You're free to do pretty much anything you want
# in terms of imports, but you should save any stateful
# initialization for the `storage_init()` method below.

import os
import sys 
import traceback
import logging
from common import get_logger, DEBUG
from ConfigParser import SafeConfigParser

log = get_logger("blockstack-storage-skel")
log.setLevel( logging.DEBUG if DEBUG else logging.INFO )

def storage_init(conf):
   """
   This method initializes the storage driver.
   It may be called multiple times, so if you need idempotency,
   you'll need to implement it yourself.

   Return True on successful initialization
   Return False on error.
   """

   # path to the CLI's configuration file (where you can stash driver-specific configuration)
   config_path = conf['path']
   if os.path.exists( config_path ):

       parser = SafeConfigParser()
        
       try:
           parser.read(config_path)
       except Exception, e:
           log.exception(e)
           return False

       # TODO load config here

   # TODO do initialization here
   return True 


def handles_url( url ):
    """
    Does this storage driver handle this kind of URL?

    It is okay if other drivers say that they can handle it.
    This is used by the storage system to quickly filter out
    drivers that don't handle this type of URL.

    A common strategy is simply to check if the scheme
    matches what your driver does.  Another common strategy
    is to check if the URL matches a particular regex.
    """

    return False


def make_mutable_url( data_id ):
   """
   This method creates a URL, given an (opaque) data ID string.
   The data ID string will be printable, but it is not guaranteed to 
   be globally unqiue.  It is opaque--do not assume anything about its
   structure.

   The URL does not need to contain the data ID or even be specific to it.
   It just needs to contain enough information that it can be used by
   get_mutable_handler() below.

   This method may be called more than once per data_id, and may be called
   independently of get_mutable_handler() below (which consumes this URL).

   Returns a string
   """

   return None
   

def get_immutable_handler( data_hash, **kw ):
   """
   Given a cryptographic hash of some data, go and fetch it.
   This is used by the immutable data API, whereby users can 
   add and remove data hashes in their zone file (hence the term
   "immutable").  The method that puts data for this method
   to fetch is put_immutable_handler(), described below.

   Drivers are encouraged but not required to implement this method.
   A common strategy is to treat the data_hash like the data_id in
   make_mutable_url().

   **kw contains hints from Blockstack about the nature of the request.
   TODO: document them here.

   Returns the data on success.  It must hash to data_hash (sha256)
   Returns None on error.  Does not raise an exception.
   """
   
   return None


def get_mutable_handler( url, **kw ):
   """
   Given the URL to some data generated by an earlier call to
   make_mutable_url().

   **kw contains hints from Blockstack about the nature of the request.
   TODO: document them here.

   Drivers are encouraged but not required to implement this method.

   Returns the data on success.  The driver is not expected to e.g. verify
   its authenticity (Blockstack will take care of this).
   Return None on error.  Does not raise an exception.
   """
   
   return None


def put_immutable_handler( data_hash, data_txt, txid, **kw ):
   """
   Store data that was written by the immutable data API.
   That is, the user updated their zone file and added a data
   hash to it.  This method is given the data's hash (sha256),
   the data itself (as a string), and the transaction ID in the underlying
   blockchain (i.e. as "proof-of-payment").

   The driver should store the data in such a way that a
   subsequent call to get_immutable_handler() with the same
   data hash returns the given data here.

   **kw contains hints from Blockstack about the nature of the request.
   TODO: document these.

   Drivers are encouraged but not required to implement this method.
   Read-only data sources like HTTP servers would not implement this
   method, for example.

   Returns True on successful storage
   Returns False on failure.  Does not raise an exception
   """
   
   return False


def put_mutable_handler( data_id, data_txt, **kw ):
   """
   Store (signed) data to this storage provider.  The only requirement
   is that a call to get_mutable_url(data_id) must generate a URL that
   can be fed into get_mutable_handler() to get the data back.  That is,
   the overall flow will be:

   # store data 
   rc = put_mutable_handler( data_id, data_txt, **kw )
   if not rc:
      # error path...

   # ... some time later ...
   # get the data back
   data_url = get_mutable_url( data_id )
   assert data_url 

   data_txt_2 = get_mutable_handler( data_url, **kw )
   if data_txt_2 is None:
      # error path...

   assert data_txt == data_txt_2

   The data_txt argument is the data itself (as a string).
   **kw contains hints from the Blockstack implementation.
   TODO: document these.

   Returns True on successful store
   Returns False on error.  Does not raise an exception
   """

   return False
   

def delete_immutable_handler( data_hash, txid, tombstone, **kw ):
   """
   Delete immutable data.  Called when the user removed a datum's hash
   from their zone file, and the driver must now go and remove the data
   from the storage provider.

   The driver is given the hash of the data (data_hash) and the underlying
   blockchain transaction ID (txid).
   
   The tombstone argument is used to prove to the driver that
   the request to delete data corresponds to an earlier request to store data.
   sig_data_txid is the signature over the string
   "delete:{}{}".format(data_hash, txid).  The user's data private key is
   used to generate the signature.  Most driver implementations
   can ignore this, but some storage systems with weak consistency 
   guarantees may find it useful in order to NACK outstanding
   writes.

   **kw are hints from Blockstack to the driver.
   TODO: document these

   Returns True on successful deletion
   Returns False on failure.  Does not raise an exception.
   """
   
   return False 


def delete_mutable_handler( data_id, tombstone, **kw ):
   """
   Delete mutable data.  Called when user requested that some data
   stored earlier with put_mutable_handler() be deleted.

   The tombstone argument is used to prove to the driver and
   underlying storage system that the
   request to delete the data corresponds to an earlier request
   to store it.  It is the signature over the string 
   "delete:{}".format(data_id).  Most driver implementations can
   ignore this; it's meant for use with storage systems with
   weak consistency guarantees.

   **kw are hints from Blockstack to the driver.
   TODO: document these

   Returns True on successful deletion
   Returns False on failure.  Does not raise an exception.
   """
   False

   
if __name__ == "__main__":
   """
   Unit tests would go here.
   """
   pass
