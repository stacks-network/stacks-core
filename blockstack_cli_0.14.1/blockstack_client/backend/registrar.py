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

import os
import sys
import random
import signal
import base64
import copy

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

import signal
from time import sleep
import json
import socket
import threading
import time
import tempfile
from keylib import ECPrivateKey

import blockstack_profiles
import blockstack_zones

from .queue import get_queue_state, in_queue, queue_removeall
from .queue import queue_cleanall, queue_find_accepted

from .nameops import async_preorder, async_register, async_update, async_transfer, async_renew, async_revoke
from .blockchain import get_block_height

from ..keys import get_data_privkey_info, is_singlesig, is_multisig, get_privkey_info_address, get_privkey_info_params, encrypt_private_key_info, decrypt_private_key_info
from ..proxy import is_name_registered, is_zonefile_hash_current, is_name_owner, get_default_proxy, get_name_blockchain_record, get_name_cost, get_atlas_peers
from ..profile import get_and_migrate_profile, zonefile_data_replicate
from ..user import make_empty_user_zonefile, is_user_zonefile 
from ..storage import put_mutable_data, put_immutable_data, hash_zonefile, get_zonefile_data_hash
from ..data import get_profile_timestamp, set_profile_timestamp

from .crypto.utils import aes_decrypt, aes_encrypt

from ..constants import SLEEP_INTERVAL, CONFIG_PATH, DEFAULT_QUEUE_PATH
from ..config import get_config, get_logger, url_to_host_port

DEBUG = True

__plugin_state = None
log = get_logger("blockstack-client-registrar")


def get_rpc_token(config_path=CONFIG_PATH):
    """
    Get the RPC token used for talking to the
    registrar functions in the local RPC endpoint.
    """
    config = get_config(config_path)
    return config.get('rpc_token', None )


def get_plugin_state(config_path=None, proxy=None):
    """
    Create singleton plugin state.
    """
    global __plugin_state
    if __plugin_state is None:
        raise Exception("State is not initialized")

    state = __plugin_state

    if config_path is None:
        config_path = state.config_path
        if config_path is None:
            config_path = CONFIG_PATH

    if proxy is None:
        proxy = get_default_proxy(config_path=config_path)

    return (state, config_path, proxy)


def set_plugin_state(config_path=None):
    """
    Set singleton state 
    """
    global __plugin_state
    assert config_path is not None

    # if we're already running, then bail
    if RegistrarWorker.is_lockfile_valid( config_path ):
        log.debug("RegistrarWorker already initialized")
        return None

    log.info("Initialize Registrar State from %s" % (config_path))
    __plugin_state = RegistrarState(config_path)
    __plugin_state.start()
    return __plugin_state


def plugin_shutdown(config_path=None):
    """
    Shut down existing state
    """
    global __plugin_state
    if __plugin_state is None:
        return

    log.info("Shut down Registrar State")
    __plugin_state.request_stop()
    __plugin_state.join()
    __plugin_state = None


class RegistrarWorker(threading.Thread):
    """
    Worker thread for waiting for transactions to go through.
    """
    def __init__(self, config_path):
        super(RegistrarWorker, self).__init__()

        self.config_path = config_path
        config = get_config(config_path)
        self.queue_path = config['queue_path']
        self.poll_interval = int(config['poll_interval'])
        self.rpc_token = config['rpc_token']
        self.api_port = int(config['api_endpoint_port'])
        self.running = True
        self.lockfile_path = None
        self.required_storage_drivers = config.get('storage_drivers_required_write', None)
        if self.required_storage_drivers is None:
            self.required_storage_drivers = config.get("storage_drivers", "").split(",")
        else:
            self.required_storage_drivers = self.required_storage_drivers.split(",")

        log.debug("Queue path:      %s" % self.queue_path)
        log.debug("Poll interval:   %s" % self.poll_interval)
        log.debug("API port:        %s" % self.api_port)
        log.debug("Storage:         %s" % ",".join(self.required_storage_drivers))


    @classmethod 
    def register_preordered_name( cls, name_data, payment_privkey_info, owner_privkey_info, proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH ):
        """
        Given a preordered name, go register it.
        Return the result of broadcasting the registration operation on success (idempotent--if already broadcasted, then return the broadcast information).
        Return {'error': ...} on error
        Return {'error': ..., 'already_registered': True} if the name is already registered
        Return {'error': ..., 'not_preordered': True} if the name was not preordered
        """
        if proxy is None:
            proxy = get_default_proxy(config_path=config_path)

        if not is_name_registered( name_data['fqu'], proxy=proxy ):
            if in_queue( "preorder", name_data['fqu'], path=queue_path ):
                if not in_queue("register", name_data['fqu'], path=queue_path):
                    # was preordered but not registered
                    # send the registration
                    owner_address = get_privkey_info_address( owner_privkey_info )
                    owner_privkey_params = get_privkey_info_params( owner_privkey_info )

                    log.debug('Send async register for {}'.format(name_data['fqu']))
                    res = async_register( name_data['fqu'], payment_privkey_info, owner_address, owner_privkey_params=owner_privkey_params, proxy=proxy, config_path=config_path, queue_path=queue_path )
                    return res
                else:
                    # already queued 
                    reg_result = queuedb_find( "register", name_data['fqu'], limit=1, path=queue_path )
                    if len(reg_result) == 1:
                        log.debug('Already queued for register: {}'.format(name_data['fqu']))
                        return {'status': True, 'transaction_hash': reg_result[0]['tx_hash']}
                    else:
                        raise Exception("Inconsistency: name '%s' is queued and then unqueued" % name_data['fqu'])

            else:
                log.error('Not preordered: {}'.format(name_data['fqu']))
                return {'error': 'Name "%s" is not preorded' % name_data['fqu'], 'not_preordered': True}

        else:
            log.error('Already registered: {}'.format(name_data['fqu']))
            return {'error': 'Name "%s" is already registered' % name_data['fqu'], 'already_registered': True}

    
    @classmethod
    def init_profile( cls, name_data, proxy=None, config_path=CONFIG_PATH, queue_path=DEFAULT_QUEUE_PATH ):
        """
        Given a newly-registered name, go broadcast the hash of its empty zonefile.
        Idempotent--if the name is already migrated, then return the result of the pending transaction
        Return {'status': True, 'transaction_hash': ..., 'zonefile_hash': ...} on success
        Return {'error': ...} on error
        """
        if proxy is None:
            proxy = get_default_proxy(config_path=config_path)

        if in_queue('update', name_data['fqu'], path=queue_path):
            # already processed 
            up_result = queuedb_find( "update", name_data['fqu'], limit=1, path=queue_path )
            if len(up_result) == 1:
                return {'status': True, 'transaction_hash': up_result[0]['tx_hash'], 'zonefile_hash': up_result[0].get('zonefile_hash', None)}

            else:
                raise Exception("Queue inconsistency: name '%s' is and is not pending update" % up_result['fqu'])

        res = migrate( name_data['fqu'], config_path=config_path, proxy=proxy )
        assert 'success' in res

        if not res['success']:
            log.error("migrate %s: %s" % (name_data['fqu'], res['error']))
            return {'error': res['error']}
        else:
            try:
                assert 'transaction_hash' in res
                assert 'zonefile_hash' in res
            except:
                raise Exception("Invalid response\n%s\n" % json.dumps(res, indent=4, sort_keys=True))

            return {'status': True, 'transaction_hash': res['transaction_hash'], 'zonefile_hash': res['zonefile_hash']}


    @classmethod
    def init_profiles( cls, queue_path, config_path=CONFIG_PATH, proxy=None ):
        """
        Find all confirmed registrations, create empty zonefiles for them and broadcast their hashes to the blockchain.
        Queue up the zonefiles and profiles for subsequent replication.
        Return {'status': True} on success
        Return {'error': ...} on failure
        """
        if proxy is None:
            proxy = get_default_proxy(config_path=config_path)

        ret = {'status': True}
        registers = cls.get_confirmed_registers( config_path, queue_path )
        for register in registers:

            # already migrated?
            if in_queue("update", register['fqu'], path=queue_path):
                log.warn("Already initialized profile for name '%s'" % register['fqu'])
                queue_removeall( [register], path=queue_path )
                continue

            log.debug("Register for '%s' (%s) is confirmed!" % (register['fqu'], register['tx_hash']))
            res = cls.init_profile( register, proxy=proxy, queue_path=queue_path, config_path=config_path )
            if 'error' in res:
                log.error("Failed to make name profile for %s: %s" % (register['fqu'], res['error']))
                ret = {'error': 'Failed to set up name profile'}

            else:
                # success!
                log.debug("Sent update for '%s'" % register['fqu'])
                queue_removeall( [register], path=queue_path )

        return ret


    @classmethod
    def get_confirmed_registers( cls, config_path, queue_path ):
        """
        Find all the confirmed registers
        """
        accepted = queue_find_accepted( "register", path=queue_path, config_path=config_path )
        return accepted


    @classmethod
    def get_confirmed_preorders( cls, config_path, queue_path ):
        """
        Find all the confirmed preorders
        """
        accepted = queue_find_accepted( "preorder", path=queue_path, config_path=config_path )
        return accepted


    @classmethod 
    def get_confirmed_updates( cls, config_path, queue_path ):
        """
        Find all confirmed updates
        """
        accepted = queue_find_accepted( "update", path=queue_path, config_path=config_path )
        return accepted


    @classmethod
    def get_confirmed_transfers( cls, config_path, queue_path ):
        """
        Find all confirmed transfers
        """
        accepted = queue_find_accepted( "transfer", path=queue_path, config_path=config_path )
        return accepted


    @classmethod 
    def register_preorders( cls, queue_path, wallet_data, config_path=CONFIG_PATH, proxy=None ):
        """
        Find all confirmed preorders, and register them.
        Return {'status': True} on success
        Return {'error': ...} on error
        'names' maps to the list of queued name data for names that were registered
        """

        if proxy is None:
            proxy = get_default_proxy(config_path=config_path)

        ret = {'status': True}
        preorders = cls.get_confirmed_preorders( config_path, queue_path )
        for preorder in preorders:

            log.debug("Preorder for '%s' (%s) is confirmed!" % (preorder['fqu'], preorder['tx_hash']))
            
            # did we already register?
            if in_queue("register", preorder['fqu'], path=queue_path):
                log.warn("Already queued name '%s' for registration" % preorder['fqu'])
                queue_removeall( [preorder], path=queue_path )
                continue

            res = cls.register_preordered_name( preorder, wallet_data['payment_privkey'], wallet_data['owner_privkey'], proxy=proxy, config_path=config_path, queue_path=queue_path )
            if 'error' in res:
                if res.get('already_registered'):
                    # can clear out, this is a dup
                    log.debug("%s is already registered!" % preorder['fqu'])
                    queue_removeall( [preorder], path=queue_path )

                else:
                    log.error("Failed to register preordered name %s: %s" % (preorder['fqu'], res['error']))
                    ret = {'error': 'Failed to preorder a name'} 

            else:
                # clear 
                log.debug("Sent register for %s" % preorder['fqu'] )
                queue_removeall( [preorder], path=queue_path )

        return ret


    @classmethod
    def clear_confirmed( cls, config_path, queue_path, proxy=None ):
        """
        Find all confirmed update, transfer, etc. transactions, and clear them out
        Return {'status': true} on success
        Return {'error': ...} on failure
        """
        for queue_name in ['transfer']:
            accepted = queue_find_accepted( queue_name, path=queue_path, config_path=config_path )

            if len(accepted) > 0:
                log.debug("Clear %s confirmed %s operations" % (len(accepted), queue_name))
                queue_removeall( accepted, path=queue_path )

        return {'status': True}

    
    @classmethod 
    def replicate_profile_data( cls, name_data, atlas_servers, wallet_data, storage_drivers, config_path, proxy=None ):
        """
        Given an update queue entry,
        replicate the zonefile to as many
        blockstack atlas servers as we can.
        If given, replicate the profile as well.
        @atlas_servers should be a list of (host, port)
        Return {'status': True} on success
        Return {'error': ...} on error
        """
     
        # is the zonefile hash replicated?
        zonefile_data = name_data['zonefile']
        if zonefile_data is None:
            log.debug("No zonefile to replicate for %s" % name_data['fqu'])
            return {'status': True}

        zonefile_hash = name_data.get('zonefile_hash', None)
        if zonefile_hash is None:
            zonefile_hash = get_zonefile_data_hash( zonefile_data )

        name_rec = get_name_blockchain_record( name_data['fqu'], proxy=proxy )
        if 'error' in name_rec:
            return name_rec

        if os.environ.get("BLOCKSTACK_TEST", None) == "1":
            log.debug("Replicate zonefile %s (blockchain: %s)\ndata:\n%s" % (zonefile_hash, name_rec['value_hash'], base64.b64encode(zonefile_data)))

        if str(name_rec['value_hash']) != zonefile_hash:
            log.error("Zonefile %s has not been confirmed yet (still on %s)" % (zonefile_hash, name_rec['value_hash']))
            return {'error': 'Zonefile hash not yet replicated'}

        res = zonefile_data_replicate( name_data['fqu'], zonefile_data, name_data['tx_hash'], atlas_servers, config_path=config_path, storage_drivers=storage_drivers )
        if 'error' in res:
            log.error("Failed to replicate zonefile %s for %s: %s" % (zonefile_hash, name_data['fqu'], res['error']))
            return res

        log.info("Replicated zonefile data for %s to %s server(s)" % (name_data['fqu'], len(res['servers'])))

        # replicate profile to storage, if given
        # use the data keypair
        if name_data.has_key('profile') and name_data['profile'] is not None:
            # only works this is actually a zonefile, since we need to use
            # the zonefile to find the appropriate data private key.
            zonefile = None
            try:
                zonefile = blockstack_zones.parse_zone_file( zonefile_data )
                assert is_user_zonefile( zonefile )
            except Exception, e:
                if os.environ.get("BLOCKSTACK_TEST", None) == 1:
                    log.exception(e)

                log.warning("Not a zone file; not replicating profile for %s" % name_data['fqu'])
                return {'status': True}

            data_privkey = get_data_privkey_info( zonefile, wallet_keys=wallet_data, config_path=config_path )
            assert data_privkey is not None, "No data private key"

            log.info("Replicate profile data for %s to %s" % (name_data['fqu'], ",".join(storage_drivers)))
            
            profile_payload = copy.deepcopy(name_data['profile'])
            profile_payload = set_profile_timestamp(profile_payload)

            rc = put_mutable_data( name_data['fqu'], profile_payload, data_privkey, required=storage_drivers )
            if not rc:
                log.info("Failed to replicate profile for %s" % (name_data['fqu']))
                return {'error': 'Failed to store profile'}
            else:
                log.info("Replicated profile for %s" % (name_data['fqu']))
                return {'status': True}

        else:
            log.info("No profile to replicate for '%s'" % (name_data['fqu']))
            return {'status': True}


    @classmethod
    def replicate_profiles( cls, queue_path, atlas_servers, wallet_data, storage_drivers, config_path=CONFIG_PATH, proxy=None ):
        """
        Replicate all zonefiles for each confirmed update.
        Remove successfully-replicated updates
        @atlas_servers should be a list of (host, port)
        """
        ret = {'status': True} 
        updates = cls.get_confirmed_updates( config_path, queue_path )
        for update in updates:
            log.debug("Zonefile update on '%s' (%s) is confirmed!  New hash is %s" % (update['fqu'], update['tx_hash'], update['zonefile_hash']))
            res = cls.replicate_profile_data( update, atlas_servers, wallet_data, storage_drivers, config_path, proxy=proxy )
            if 'error' in res:
                log.error("Failed to update %s: %s" % (update['fqu'], res['error']))
                ret = {'error': 'Failed to finish an update'}

            else:
                # clear 
                queue_removeall( [update], path=queue_path )

        return ret
        

    @classmethod 
    def get_atlas_server_list( cls, config_path ):
        """
        Get the list of atlas servers to which to replicate zonefiles
        Returns [(host, port)] on success
        Returns {'error': ...} on error
        """
        conf = get_config(config_path)
        servers = ['{}:{}'.format(conf['server'], conf['port'])]
        server_hostport = '{}:{}'.format(conf['server'], conf['port'])

        atlas_peers_res = {}
        try:
            atlas_peers_res = get_atlas_peers( server_hostport )
            assert 'error' not in atlas_peers_res
           
            servers += atlas_peers_res['peers']

        except AssertionError as ae:
            log.exception(ae)
            log.error('Error response from {}: {}'.format(server_hostport, atlas_peers_res['error']))
            return {'error': 'Failed to get valid response'}
        except socket.error, se:
            log.exception(se)
            log.warning('Failed to find Atlas peers of {}'.format(server_hostport))
            return {'error': 'Failed to get atlas peers due to socket error'}
        except Exception as e:
            log.exception(e)
            return {'error': 'Failed to contact atlas peer'}
            
        servers = list(set([str(hp) for hp in servers]))
        log.debug("Servers: {}".format(servers))

        return [url_to_host_port(hp) for hp in servers]


    def cleanup_lockfile(self, path):
        """
        Remove a lockfile (exit handler)
        """
        if self.lockfile_path is None:
            return

        try:
            os.unlink(self.lockfile_path)
            self.lockfile_path = None
        except:
            pass


    def request_stop(self):
        """
        Stop this thread
        """
        self.running = False


    @classmethod
    def is_lockfile_stale( cls, path ):
        """
        Is the given lockfile stale?
        """
    
        with open(path, "r") as f:
            dat = f.read()
            try:
                pid = int(dat.strip())
            except:
                # corrupt
                pid = -1

        return pid != os.getpid()


    @classmethod
    def lockfile_write( cls, fd ):
        """
        Put a lockfile
        Return True on success
        Return False on error
        """
        
        buf = "%s\n" % os.getpid()
        nw = 0
        while nw < len(buf):
            try:
                rc = os.write( fd, buf[nw:] )
                nw += rc
            except:
                log.error("Failed to write lockfile")
                return False

        return True


    @classmethod
    def get_lockfile_path( cls, config_path ):
        """
        Get the path to the lockfile
        """
        return os.path.join( os.path.dirname(config_path), "registrar.lock" )


    @classmethod 
    def is_lockfile_valid( cls, config_path ):
        """
        Does the lockfile exist and does it correspond
        to a running registrar?
        """
        lockfile_path = cls.get_lockfile_path( config_path )
        if os.path.exists(lockfile_path):
            # is it stale?
            if cls.is_lockfile_stale( lockfile_path ):
                return False

            else:
                # not stale
                return True

        else:
            return False


    def run(self):
        """
        Watch the various queues:
        * if we find an accepted preorder, send the accompanying register
        * if we find an accepted update, replicate the accompanying zonefile
        """
        failed = False
        poll_interval = self.poll_interval

        log.info("Registrar worker entered")

        # set up a lockfile
        self.lockfile_path = RegistrarWorker.get_lockfile_path( self.config_path )
        if not RegistrarWorker.is_lockfile_valid( self.config_path ):
            if os.path.exists(self.lockfile_path):
                log.debug("Removing stale lockfile")
                os.unlink(self.lockfile_path)

        else:
            log.debug("Extra worker thread exiting (lockfile exists and is valid)")
            return

        try:
            fd, path = tempfile.mkstemp(prefix=".registrar.lock.", dir=os.path.dirname(self.config_path))
            os.link( path, self.lockfile_path )
            
            try:
                os.unlink(path)
            except:
                pass

            # success!  write the lockfile
            rc = RegistrarWorker.lockfile_write( fd )
            os.close( fd )

            if not rc:
                log.error("Failed to write lockfile")
                return

        except (IOError, OSError):
            try:
                os.unlink(path)
            except:
                pass

            log.debug("Extra worker exiting (failed to lock)")
            return

        log.debug("Registrar worker starting up")

        while self.running:

            failed = False
            wallet_data = None
            proxy = get_default_proxy( config_path=self.config_path )

            try:
                wallet_data = get_wallet( self.rpc_token, config_path=self.config_path, proxy=proxy )

                # wait until the owner address is set 
                while ('error' in wallet_data or wallet_data['owner_address'] is None) and self.running:
                    log.debug("Owner address not set... (%s)" % wallet_data.get("error", ""))
                    wallet_data = get_wallet( self.rpc_token, config_path=self.config_path, proxy=proxy )
                    time.sleep(1.0)
                
                # preemption point
                if not self.running:
                    break

            except Exception, e:
                log.exception(e)
                break

            try:
                # see if we can complete any registrations
                # clear out any confirmed preorders
                log.debug("register all pending preorders in %s" % (self.queue_path))
                res = RegistrarWorker.register_preorders( self.queue_path, wallet_data, config_path=self.config_path, proxy=proxy )
                if 'error' in res:
                    log.warn("Registration failed: %s" % res['error'])

                    # try exponential backoff
                    failed = True
                    poll_interval = 1.0

            except Exception, e:
                log.exception(e)
                failed = True

            try:
                # see if we can put any zonefiles
                # clear out any confirmed registers
                log.debug("put zonefile hashes for registered names in %s" % (self.queue_path))
                res = RegistrarWorker.init_profiles( self.queue_path, config_path=self.config_path, proxy=proxy )
                if 'error' in res:
                    log.warn('zonefile hash broadcast failed: %s' % res['error'])

                    # try exponential backoff 
                    failed = True
                    poll_interval = 1.0

            except Exception, e:
                log.exception(e)
                failed = True

            try:
                # see if we can replicate any zonefiles and profiles
                # clear out any confirmed updates
                log.debug("replicate all pending zonefiles and profiles in %s" % (self.queue_path))
                servers = RegistrarWorker.get_atlas_server_list( self.config_path )
                if 'error' in servers:
                    log.warn('Zonefile/profile replicaton failed: failed to get server list: {}'.format(servers['error']))

                    # try exponential backoff 
                    failed = True
                    poll_interval = 1.0

                else:
                    res = RegistrarWorker.replicate_profiles( self.queue_path, servers, wallet_data, self.required_storage_drivers, config_path=self.config_path, proxy=proxy )
                    if 'error' in res:
                        log.warn("Zonefile/profile replication failed: %s" % res['error'])

                        # try exponential backoff
                        failed = True
                        poll_interval = 1.0

            except Exception, e:
                log.exception(e)
                failed = True

            try:
                # see if we can remove any other confirmed operations, besides preorders, registers, and updates
                log.debug("clean out other confirmed operations")
                res = RegistrarWorker.clear_confirmed( self.config_path, self.queue_path, proxy=proxy )
                if 'error' in res:
                    log.warn("Failed to clear out some operations: %s" % res['error'])

                    # try exponential backoff
                    failed = True
                    poll_interval = 1.0

            except Exception, e:
                log.exception(e)
                failed = True

            # if we failed a step, then try again quickly with exponential backoff
            if failed:
                poll_interval = 2 * poll_interval + random.random() * poll_interval

            else:
                # succeeded. resume normal polling 
                poll_interval = self.poll_interval
           
            try:
                log.debug("Sleep for %s" % poll_interval)
                for i in xrange(0, int(poll_interval)):
                    time.sleep(1)

                    # preemption point
                    if not self.running:
                        break

            except:
                # interrupted
                log.debug("Sleep interrupted")
                break

            # remove expired 
            log.debug("Cleaning all queues in %s" % self.queue_path)
            queue_cleanall( path=self.queue_path, config_path=self.config_path )

        log.info("Registrar worker exited")
        self.cleanup_lockfile( self.lockfile_path )


class RegistrarState(object):
    """
    State bundle for the RPC calls
    """
    finished = False

    payment_address = None
    owner_address = None

    encrypted_payment_privkey_info = None
    encrypted_owner_privkey_info = None
    encrypted_data_privkey_info = None

    server_started_at = None
    registrar_worker = None
    queue_path = None

    def __init__(self, config_path):

        self.config_path = config_path
        conf = get_config(config_path)
        self.queue_path = conf['queue_path']
        log.info("Registrar initialized (config: %s, queues: %s)" % (config_path, self.queue_path))
        self.server_started_at = get_block_height( config_path=config_path )
        self.registrar_worker = RegistrarWorker( config_path )


    def start(self):
        self.registrar_worker.start()

    def request_stop(self):
        log.debug("Registrar worker request stop")
        self.registrar_worker.request_stop()

    def join(self):
        log.debug("Registrar worker join")
        self.registrar_worker.join()


def ping():
    """
    Check if RPC daemon is alive
    """

    data = {'status': 'alive'}
    return data


def state():
    """
    Return status on current registrations
    """

    state, config_path, proxy = get_plugin_state()
    log.debug("Get queue state from %s" % state.queue_path)
    data = get_queue_state(path=state.queue_path)
    return json.dumps(data)


def set_wallet(payment_keypair, owner_keypair, data_keypair, config_path=None, proxy=None):
    """
    Keeps payment privkey in memory (instead of disk)
    for the time that server is alive.

    Each _keypair is a list or tuple with two items: the address, and the private key information
    (note that the private key information can be either a private key, or a multisig info dict).

    Return {'success': True} on success
    Return {'error': ...} on error
    """
    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    rpc_token = get_rpc_token(config_path)

    # sanity check...
    if not is_singlesig( payment_keypair[1] ) and not is_multisig( payment_keypair[1] ):
        return {'error': 'Invalid payment key info'}

    if not is_singlesig( owner_keypair[1] ) and not is_multisig( owner_keypair[1] ):
        return {'error': 'Invalid owner key info'}

    if not is_singlesig( data_keypair[1] ):
        return {'error': 'Invalid data key info'}

    state.payment_address = payment_keypair[0]
    state.owner_address = owner_keypair[0]

    enc_payment_info = encrypt_private_key_info(payment_keypair[1], rpc_token )
    enc_owner_info = encrypt_private_key_info(owner_keypair[1], rpc_token )
    enc_data_info = encrypt_private_key_info(data_keypair[1], rpc_token )

    if 'error' in enc_payment_info:
        return {'error': 'Failed to encrypt payment key: %s' % enc_payment_info['error']}

    if 'error' in enc_owner_info:
        return {'error': 'Failed to encrypt owner key: %s' % enc_owner_info['error']}

    if 'error' in enc_data_info:
        return {'error': 'Failed to encrypt data key: %s' % enc_data_info['error']}

    state.encrypted_payment_privkey_info = enc_payment_info['encrypted_private_key_info']['private_key_info']
    state.encrypted_owner_privkey_info = enc_owner_info['encrypted_private_key_info']['private_key_info']
    state.encrypted_data_privkey_info = enc_data_info['encrypted_private_key_info']['private_key_info']

    data = {}
    data['success'] = True

    log.debug("Wallet set (%s, %s, %s)" % (state.payment_address, state.owner_address, data_keypair[0]))
    return data


def get_start_block(config_path=None, proxy=None):
    """
    Get the block at which rpc daemon was started
    Return None if not set
    """
    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    return state.server_started_at


def get_wallet_payment_privkey_info(config_path=None, proxy=None):
    """
    Get the decrypted payment private key info from the wallet
    Return None if not set
    """
    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    rpc_token = get_rpc_token(config_path)
    if state.encrypted_payment_privkey_info is None:
        return None

    privkey_info = decrypt_private_key_info( state.encrypted_payment_privkey_info, rpc_token )
    if 'error' in privkey_info:
        log.error("Failed to decrypt payment key: %s" % privkey_info['error'])
        return None

    return privkey_info['private_key_info']


def get_wallet_owner_privkey_info(config_path=None, proxy=None):
    """
    Get the decrypted owner private key info from the wallet
    Return None if not set
    """
    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    rpc_token = get_rpc_token(config_path)
    if state.encrypted_owner_privkey_info is None:
        return None

    privkey_info = decrypt_private_key_info(state.encrypted_owner_privkey_info, rpc_token)
    if 'error' in privkey_info:
        log.error("Failed to decrypt owner key: %s" % privkey_info['error'])
        return None

    return privkey_info['private_key_info']


def get_wallet_data_privkey_info(config_path=None, proxy=None):
    """
    Get the decrypted data private key info from the wallet
    Return None if not set
    """
    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    rpc_token = get_rpc_token(config_path=config_path)
    if state.encrypted_data_privkey_info is None:
        return None 

    privkey_info = decrypt_private_key_info(state.encrypted_data_privkey_info, rpc_token)
    if 'error' in privkey_info:
        log.error("Failed to decrypt data key: %s" % privkey_info['error'])
        return None

    return privkey_info['private_key_info']


def get_wallet(rpc_token=None, config_path=None, proxy=None):
    """
    Keeps payment privkey in memory (instead of disk)
    for the time that server is alive
    Return the wallet (as a JSON dict) on success
    Return {'error':...} on error
    """

    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    data = {}
    valid_rpc_token = get_rpc_token(config_path=config_path)

    if str(valid_rpc_token) != str(rpc_token):
        data['error'] = "Incorrect RPC token"
        return data

    data_privkey_info = get_wallet_data_privkey_info()
    if data_privkey_info is None:
        data['error'] = "Unable to decrypt data private key"
        return data

    data['payment_address'] = state.payment_address
    data['owner_address'] = state.owner_address
    data['data_pubkey'] = ECPrivateKey( data_privkey_info ).public_key().to_hex()

    data['payment_privkey'] = get_wallet_payment_privkey_info()
    data['owner_privkey'] = get_wallet_owner_privkey_info()
    data['data_privkey'] = get_wallet_data_privkey_info()

    if data['payment_privkey'] is None or data['owner_privkey'] is None or data['data_privkey'] is None:
        data['error'] = "Failed to load private keys (wrong password?)"

    return data


def preorder(fqu, config_path=None, proxy=None):
    """
    Send preorder transaction and enter it in queue.
    The entered registration is picked up
    by the monitor process.
    Return {'success': True, ...} on success
    Return {'error': ...} on error
    """

    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    data = {}

    if state.payment_address is None or state.owner_address is None:
        log.debug("Wallet is not unlocked")
        data['success'] = False
        data['error'] = "Wallet is not unlocked."
        return data

    if in_queue("preorder", fqu, path=state.queue_path):
        log.debug("Already enqueued: %s" % fqu)
        data['success'] = False
        data['error'] = "Already in queue."
        return data

    cost_info = None
    cost_info = get_name_cost( fqu, proxy=proxy )
    if 'error' in cost_info:
        data['success'] = False
        data['error'] = "Failed to look up name cost: %s" % cost_info['error']
        return data

    payment_privkey_info = get_wallet_payment_privkey_info()
    owner_privkey_info = get_wallet_owner_privkey_info()
    owner_privkey_params = get_privkey_info_params( owner_privkey_info )
    owner_address = get_privkey_info_address( owner_privkey_info )

    if not is_name_registered(fqu, proxy=proxy):
        resp = async_preorder(fqu, payment_privkey_info, owner_address, cost_info['satoshis'], owner_privkey_params=owner_privkey_params, proxy=proxy, config_path=config_path, queue_path=state.queue_path)
    else:
        return {'success': False, 'error': "Name is already registered"}

    if 'error' not in resp:
        data['success'] = True
        data['message'] = "The name has been queued up for registration and"
        data['message'] += " will take a few hours to go through. You can"
        data['message'] += " check on the status at any time by running"
        data['message'] += " 'blockstack info'."
        data['transaction_hash'] = resp['transaction_hash']
    else:
        data['success'] = False
        data['message'] = "Couldn't broadcast transaction. You can try again."
        data['error'] = resp['error']

    return data


def update( fqu, zonefile_txt_b64, profile, zonefile_hash, config_path=None, proxy=None ):
    """
    Send a new zonefile hash.  Queue the zonefile data for subsequent replication.
    """

    assert zonefile_txt_b64 is not None or zonefile_hash is not None, "need zonefile or zonefile hash"
    
    zonefile_txt = None
    if zonefile_txt_b64 is not None:
        try:
            zonefile_txt = base64.b64decode(zonefile_txt_b64)
        except:
            return {'error': 'Invalid base64 zonefile'}

    if zonefile_hash is None:
        zonefile_hash = get_zonefile_data_hash( zonefile_txt )
        
    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    data = {}

    if state.payment_address is None or state.owner_address is None:
        data['success'] = False
        data['error'] = "Wallet is not unlocked."
        return data

    if in_queue("update", fqu, path=state.queue_path):
        data['success'] = False
        data['error'] = "Already in queue."
        return data

    resp = None

    payment_privkey_info = get_wallet_payment_privkey_info()
    owner_privkey_info = get_wallet_owner_privkey_info()

    replication_error = None

    if not is_zonefile_hash_current(fqu, zonefile_hash, proxy=proxy ):
        # new zonefile data
        resp = async_update(fqu, zonefile_txt, profile,
                            owner_privkey_info,
                            payment_privkey_info,
                            zonefile_hash=zonefile_hash,
                            proxy=proxy,
                            config_path=config_path,
                            queue_path=state.queue_path)

    else:
        return {'success': True, 'warning': "The zonefile has not changed, so no update sent."}

    if 'error' not in resp:

        data['success'] = True
        data['message'] = "The name has been queued up for update and"
        data['message'] += " will take ~1 hour to process. You can"
        data['message'] += " check on the status at any time by running"
        data['message'] += " 'blockstack info'."
        data['transaction_hash'] = resp['transaction_hash']
        data['value_hash'] = resp['zonefile_hash']
    else:
        log.error("async_update failed with: '%s'" % resp['error'])
        data['success'] = False
        data['message'] = "Couldn't broadcast transaction. You can try again."
        data['error'] = resp['error']


    if replication_error is not None:
        data['warning'] = "Failed to replicate the zonefile ('%s')" % replication_error

    return data


def transfer(fqu, transfer_address, config_path=None, proxy=None ):
    """
    Send transfer transaction.
    Keeps the zonefile data.
    """

    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    data = {}

    if state.payment_address is None or state.owner_address is None:
        data['success'] = False
        data['error'] = "Wallet is not unlocked."
        return data

    if in_queue("transfer", fqu, path=state.queue_path):
        data['success'] = False
        data['error'] = "Already in queue."
        return data

    payment_privkey_info = get_wallet_payment_privkey_info()
    owner_privkey_info = get_wallet_owner_privkey_info()

    resp = None
    if not is_name_owner(fqu, transfer_address, proxy=proxy):
        resp = async_transfer(fqu, transfer_address,
                              owner_privkey_info,
                              payment_privkey_info,
                              proxy=proxy,
                              config_path=config_path,
                              queue_path=state.queue_path)
    
    else:
        return {'status': False, 'error': "Name is not owned."}

    if 'error' not in resp:
        data['success'] = True
        data['message'] = "The name has been queued up for transfer and"
        data['message'] += " will take ~1 hour to process. You can"
        data['message'] += " check on the status at any time by running"
        data['message'] += " 'blockstack info'."
        data['transaction_hash'] = resp['transaction_hash']
    else:
        data['success'] = False
        data['message'] = "Couldn't broadcast transaction. You can try again."
    return data


def migrate( fqu, config_path=None, proxy=None ):
    """
    Create an empty profile/zonefile for a name, and send the hash of the 
    zonefile to the blockchain.  Queue up the zonefile and profile for replication.

    Return {'success': True, 'transaciton_hash': ..., 'zonefile_hash': ...} on success
    Return {'success': True} if the profile has already been migrated
    Return {'success': False, 'error': ...} on failure
    """

    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    data = {}

    if state.payment_address is None or state.owner_address is None:
        data['success'] = False
        data['error'] = "Wallet is not unlocked."
        return data

    if in_queue("update", fqu, path=state.queue_path):
        data['success'] = False
        data['error'] = "Already in queue."
        return data

    rpc_token = get_rpc_token(config_path)
    wallet_keys = get_wallet(rpc_token=rpc_token, config_path=config_path, proxy=proxy )
    if 'error' in wallet_keys:
        log.error("Failed to get wallet: %s" % wallet_keys['error'])
        data['success'] = False
        data['error'] = 'Failed to load wallet'
        return data
   
    user_profile, user_zonefile, legacy = get_and_migrate_profile( fqu, create_if_absent=True, proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in user_profile:
        log.debug("Unable to load user zonefile for '%s': %s" % (fqu, user_profile['error']))
        return {'success': False, 'error': 'Unable to load user zonefile: %s' % user_profile['error']}

    if not legacy:
        return {'success': True}

    user_zonefile = user_zonefile['zonefile']
    user_profile = user_profile['profile']
    
    resp = None

    payment_privkey_info = get_wallet_payment_privkey_info()
    owner_privkey_info = get_wallet_owner_privkey_info()
    replication_error = None

    zonefile_txt = blockstack_zones.make_zone_file( user_zonefile )
    zonefile_hash = get_zonefile_data_hash( zonefile_txt )

    if not is_zonefile_hash_current(fqu, zonefile_hash, proxy=proxy ):
        resp = async_update(fqu, zonefile_txt, user_profile,
                            owner_privkey_info,
                            payment_privkey_info,
                            zonefile_hash=zonefile_hash,
                            proxy=proxy,
                            config_path=config_path,
                            queue_path=state.queue_path)

    else:
        return {'success': True, 'warning': "The zonefile has not changed, so no update sent."}

    if 'error' not in resp:

        data['success'] = True
        data['message'] = "The name has been queued up for update and"
        data['message'] += " will take ~1 hour to process. You can"
        data['message'] += " check on the status at any time by running"
        data['message'] += " 'blockstack info'."
        data['transaction_hash'] = resp['transaction_hash']
        data['zonefile_hash'] = resp['zonefile_hash']
        data['zonefile'] = user_zonefile
        data['profile'] = user_profile
    else:
        log.error("async_update failed with: '%s'" % resp['error'])
        data['success'] = False
        data['message'] = "Couldn't broadcast transaction. You can try again."
        data['error'] = resp['error']


    if replication_error is not None:
        data['warning'] = "Failed to replicate the zonefile ('%s')" % replication_error

    return data


def renew( fqu, renewal_fee, config_path=None, proxy=None ):
    """
    Renew a name
    """

    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    data = {}

    if state.payment_address is None or state.owner_address is None:
        data['success'] = False
        data['error'] = "Wallet is not unlocked."
        return data

    if in_queue("renew", fqu, path=state.queue_path):
        data['success'] = False
        data['error'] = "Already in queue."
        return data

    resp = None

    payment_privkey_info = get_wallet_payment_privkey_info()
    owner_privkey_info = get_wallet_owner_privkey_info()

    resp = async_renew(fqu, owner_privkey_info, payment_privkey_info, renewal_fee,
                       proxy=proxy,
                       config_path=config_path,
                       queue_path=state.queue_path)

    if 'error' not in resp:

        data['success'] = True
        data['message'] = "The name has been queued up for renewal and"
        data['message'] += " will take ~1 hour to process. You can"
        data['message'] += " check on the status at any time by running"
        data['message'] += " 'blockstack info'."
        data['transaction_hash'] = resp['transaction_hash']
    else:
        data['success'] = False
        data['message'] = "Couldn't broadcast transaction. You can try again."
        data['error'] = resp['error']


    return data



def revoke( fqu, config_path=None, proxy=None ):
    """
    Revoke a name
    """

    state, config_path, proxy = get_plugin_state(config_path=config_path, proxy=proxy)
    data = {}

    if state.payment_address is None or state.owner_address is None:
        data['success'] = False
        data['error'] = "Wallet is not unlocked."
        return data

    if in_queue("revoke", fqu, path=state.queue_path):
        data['success'] = False
        data['error'] = "Already in queue."
        return data

    resp = None

    payment_privkey_info = get_wallet_payment_privkey_info()
    owner_privkey_info = get_wallet_owner_privkey_info()

    resp = async_revoke(fqu, owner_privkey_info, payment_privkey_info,
                        proxy=proxy,
                        config_path=config_path,
                        queue_path=state.queue_path)

    if 'error' not in resp:

        data['success'] = True
        data['message'] = "The name has been queued up for renewal and"
        data['message'] += " will take ~1 hour to process. You can"
        data['message'] += " check on the status at any time by running"
        data['message'] += " 'blockstack info'."
        data['transaction_hash'] = resp['transaction_hash']
    else:
        data['success'] = False
        data['message'] = "Couldn't broadcast transaction. You can try again."
        data['error'] = resp['error']


    return data


# these are the publicly-visible RPC methods
# invoke with "backend_{method name}"
RPC_PREFIX = "backend"
RPC_METHODS = [
    ping,
    state,
    get_wallet,
    set_wallet,
    get_start_block,
    preorder,
    update,
    transfer,
    migrate,
    renew,
    revoke
]

RPC_INIT = set_plugin_state 
RPC_SHUTDOWN = plugin_shutdown
