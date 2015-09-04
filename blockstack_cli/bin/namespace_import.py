#!/usr/bin/python

import json 
import time
import os 
import sys
import traceback
import subprocess
import pprint
import pybitcoin
import binascii
import logging 

DEBUG = True

from ConfigParser import SafeConfigParser

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from blockstore import client, config

log = config.log

AVG_BLOCK_TIME = 60    # average number of seconds between blocks 
CONFIRM_DELAY = 10      # number of blocks to wait to pass before confirming that the name was registered

def pretty_dump(json_str):
    """ pretty dump
    """
    return json.dumps(json_str, sort_keys=True, indent=4, separators=(',', ': '))


def send_checkpoint( chaincom_client, privkey_str, checkpoint_str="http://blockstack.org/summit" ):
    """
    Write an OP_RETURN to the blockchain, to checkpoint our progress.
    Should be written every Nth name.
    """
    
    nulldata = binascii.hexlify( checkpoint_str )
    return pybitcoin.embed_data_in_blockchain( nulldata, privkey_str, chaincom_client, 10000, format='hex')


def namecoin_to_bitcoin_address( nmc_address ):
    """
    Convert a namecoin address to a bitcoin address.
    The only difference is the version number.
    """
    
    return pybitcoin.b58check_encode( pybitcoin.b58check_decode( nmc_address ), version_byte=0 )


def get_chaincom_api_keys( path="./chaincom.ini" ):
    """
    Read the ini-formatted file given to find chain.com keys.
    """
    
    parser = SafeConfigParser()
    parser.read( path )
    
    return parser.get("chaincom", "api_key_id"), parser.get("chaincom", "api_key_secret")


def confirm_name_imported( client, name ):
    """
    See if a name has been imported.
    """
    
    name_info = client.lookup( name )
    if 'error' in name_info:
        log.info( "confirm '%s'...no" % name )
        return False 
    
    # must be a full record 
    name_info = name_info[0]
    
    if name_info is None:
        log.info( "confirm '%s'...no" % name )
        return False 
    
    if 'address' not in name_info:
        log.info( "confirm '%s'...no" % name )
        return False 
    
    if 'value_hash' not in name_info:
        log.info( "confirm '%s'...no" % name )
        return False 
    
    if name_info['value_hash'] is None:
        log.info( "confirm '%s'...no" % name )
        return False 
    
    log.info( "confirm '%s'...yes" % name )
    return True
    

def find_imported( client, name_list ):
    """
    Find the list of names that have been imported
    """
    imported = []
    
    for name in name_list:
        if confirm_name_imported( client, name ):
            imported.append( name )
            
    return imported
        

if __name__ == "__main__":
    
    names_json = None
    names = None 
    namespace_id = None
    privkey_str = None 
    pp = pprint.PrettyPrinter()

    if len(sys.argv) != 4:
        print >> sys.stderr, "Usage: %s [json_file] [namespace_id] [private_key]"
        sys.exit(1)

    # try to connect to our broadcast provider
    try:
        chaincom_id, chaincom_secret = get_chaincom_api_keys()
    except Exception, e:
        traceback.print_exc()
        print >> sys.stderr, "Failed to get Chain.com API keys"
        sys.exit(1)
        
    chaincom_client = pybitcoin.ChainComClient( chaincom_id, chaincom_secret )

    # get our namespace's names
    try:
        with open( sys.argv[1], "r" ) as f:
           names_json = f.read()

    except Exception, e:
        traceback.print_exc()
        print >> sys.stderr, "Failed to read '%s'" % sys.argv[1]
        sys.exit(1)

    privkey_str = sys.argv[3]
    namespace_id = sys.argv[2]

    try:
        names = json.loads( names_json )
    except Exception, e:
        traceback.print_exc()
        print >> sys.stderr, "Invalid JSON file '%s'" % sys.argv[1]
        sys.exit(1)

    # recorrd name status
    logfile_path = namespace_id + ".sent"
    failed_path = namespace_id + ".failed"
    confirmed_path = namespace_id + ".confirmed"
    
    sent_names_json = []
    sent_names = {}
    
    confirmed_names = []
    
    unconfirmed_names = {}      # map name to send time
    
    failed_lines = None
    failed = []
    
    # resume from where we left off...
    try:
        # should contain newline-separated list of names we've processed so far
        if not os.path.exists( logfile_path ):
            sent_fd = open( logfile_path, "w+" )
        else:
            sent_fd = open( logfile_path, "r+" )
        
        if not os.path.exists( failed_path ):
            failed_fd = open( failed_path, "w+" )
        else:
            failed_fd = open( failed_path, "r+" )
        
        if not os.path.exists( confirmed_path ):
            confirmed_fd = open( confirmed_path, "w+" )
        else:
            confirmed_fd = open( confirmed_path, "r+" )
            
        sent_names_json = sent_fd.read().split("\n")
        confirmed_names = confirmed_fd.read().split("\n")
        failed_fd.seek( 0, 2 )
        
    except Exception, e:
        traceback.print_exc()
        print >> sys.stderr, "Failed to open '%s'" % logfile_path
        sys.exit(1)

    # get list of sent name records
    for name_json in sent_names_json:
        if len(name_json.strip()) == 0:
            continue
        
        name_rec = json.loads( name_json.strip() )
        sent_names[ name_rec['name'] ] = name_rec
    
    # connect to blockstore
    conf = config.get_config()
    proxy = client.session(conf['blockstored_server'], conf['blockstored_port'])
    
    time_of_last_confirmation = 0 
    
    # find any previously-sent-but-not-confirmed names 
    for sent_name in sent_names.keys():
        if sent_name not in confirmed_names:
            t = sent_names[sent_name].get('time', 0)
            unconfirmed_names[ sent_name ] = t
            
    # sanity check all names 
    for name in names:
        
        # must have BTC or NMC address 
        if not name.has_key('nmc_address') and not name.has_key('btc_address'):
            raise Exception("Name '%s' lacks an address" % name)
        
        # must have a profile hash 
        if not name.has_key('hash') and not name.has_key('profile_hash'):
            raise Exception("Name '%s' lacks a profile hash" % name )
    
    # do all imports
    for name in names:
        
        # every block (or on start-up), update the list of imported names
        if time_of_last_confirmation + AVG_BLOCK_TIME < time.time():
            
            log.info( "Check for confirmed names" )
            
            # get sent names that were sent more than AVG_BLOCK_TIME * CONFIRM_DELAY seconds ago 
            names_to_check = filter( lambda n: unconfirmed_names[n] + AVG_BLOCK_TIME * CONFIRM_DELAY < time.time(), unconfirmed_names.keys() )
            
            # which of our unconfirmed names have been confirmed?
            new_confirmed = find_imported( client, names_to_check )
            for confirmed_name in new_confirmed:
                
                confirmed_fd.write( "%s\n" % confirmed_name )
                confirmed_fd.flush()
                
                if confirmed_name in sent_names.keys():
                    del sent_names[confirmed_name]
                    
                confirmed_names.append( confirmed_name )
                
                del unconfirmed_names[ confirmed_name ]
                
            time_of_last_confirmation = time.time()
            
        username = name['username']
        
        if name.has_key('hash'):
            update_hash = str(name['hash'])
        elif name.has_key('profile_hash'):
            update_hash = str(name['profile_hash'])
            
        fqn = username + "." + namespace_id
        
        if fqn in confirmed_names or fqn in sent_names.keys():
            # already imported or sent
            continue 
        
        btc_address = None 
        nmc_address = None 
        address = None
        
        if name.has_key('nmc_address'):
            nmc_address = str(name['nmc_address'])
            btc_address = namecoin_to_bitcoin_address( nmc_address )
            
        elif name.has_key("btc_address"):
            btc_address = name['btc_address']
        
        log.debug( "name_import " + fqn + " " + btc_address + " " + update_hash )

        try:
            result = client.name_import( fqn, btc_address, update_hash, privkey_str )
        except Exception, e:
            log.error( "register '%s' failed:\n%s\n" % (fqn, traceback.format_exc()) )
            
            failed_fd.write( "%s\n" % (fqn))
            failed_fd.flush()
            continue 
        
        if type(result) == type([]):
            result = result[0]
        
        if 'error' in result.keys():
            log.error( "register '%s' failed:\n%s\n" % (fqn, pp.pformat(result)) )
            log.error( "Result: %s" % result)
            
            if result['error'] == 'Name already registered':
                # it's because this is confirmed already!
                log.debug("Confirmed: '%s'" % fqn)
                confirmed_fd.write( "%s\n" % fqn)
                confirmed_fd.flush()
                
                if fqn in sent_names.keys():
                    del sent_names[fqn]
                
                confirmed_names.append( fqn )
                
                if fqn in unconfirmed_names[ fqn ]:
                    del unconfirmed_names[ fqn ]
            
            else:
                failed_fd.write( "%s\n" % (fqn))
                failed_fd.flush()
                
            continue 
        
        # record progress
        # num_sent_names += 1
        
        result['name'] = fqn
        result['time'] = time.time()
        result_str = json.dumps( result )
        
        sent_fd.write( "%s\n" % result_str)
        sent_fd.flush()
        
        print pretty_dump( result )
        
        unconfirmed_names[ fqn ] = result['time']
        
        # how long are we doing to wait?
        delay = 20
        try:
            with open("delay.txt", "r") as fd:
                delay_txt = fd.read()
            
            delay = float(delay_txt.strip())
        except Exception, e:
            print >> sys.stderr, "failed to read delay.txt; assuming %s" % delay
            
        time.sleep(delay)
        
        
        """
        if (num_sent_names % 20 == 0):
            
            checkpoint_tx = send_checkpoint( chaincom_client, privkey_str )
            print pretty_dump( checkpoint_tx )
            
            time.sleep(20)
        """

    # wait for all names to confirm 
    while len(unconfirmed_names.keys()) > 0:
        
        time.sleep( AVG_BLOCK_TIME )
    
        # get sent names that were sent more than AVG_BLOCK_TIME * CONFIRM_DELAY seconds ago 
        names_to_check = filter( lambda n: unconfirmed_names[n] + AVG_BLOCK_TIME * CONFIRM_DELAY < time.time(), unconfirmed_names.keys() )
        
        log.info( "Check for %d unconfirmed name(s)" % len(names_to_check) )
        
        # which of our unconfirmed names have been confirmed?
        new_confirmed = find_imported( client, names_to_check )
        for confirmed_name in new_confirmed:
            
            confirmed_fd.write( "%s\n" % confirmed_name )
            confirmed_fd.flush()
            
            if confirmed_name in sent_names.keys():
                del sent_names[confirmed_name]
                
            confirmed_names.append( confirmed_name )
            
            del unconfirmed_names[ confirmed_name ]
