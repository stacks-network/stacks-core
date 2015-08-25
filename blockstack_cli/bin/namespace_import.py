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

from ConfigParser import SafeConfigParser

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from blockstore import client, config


def pretty_dump(json_str):
    """ pretty dump
    """
    return json.dumps(json_str, sort_keys=True, indent=4, separators=(',', ': '))


def send_checkpoint( chaincom_client, privkey_str, checkpoint_str="https://blockstack.org/summit" ):
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

    # record successfully-imported names 
    logfile_path = namespace_id + ".log"
    failed_path = namespace_id + ".failed"
    
    processed_so_far_lines = None
    processed_so_far = []
    imported_names = {}         # map fully-qualified names to their import records
    
    failed_lines = None
    failed = []
    
    # resume from where we left off...
    try:
        # should contain newline-separated list of names we've processed so far
        log_fd = open( logfile_path, "r+" )
        failed_fd = open( failed_path, "r+" )
        
        processed_so_far_lines = log_fd.read()
        failed_lines = failed_fd.read()
        
    except Exception, e:
        traceback.print_exc()
        print >> sys.stderr, "Failed to open '%s'" % logfile_path
        sys.exit(1)

    processed_so_far = processed_so_far_lines.split("\n")
    failed = failed_lines.split("\n")
    
    # each line in the log is a JSON object...
    for imported_name_json in processed_so_far:
        if len(imported_name_json.strip()) == 0:
            continue
        
        imported_name_rec = json.loads( imported_name_json.strip() )
        imported_names[ imported_name_rec['name'] ] = imported_name_rec
    
    # connect to blockstore
    conf = config.get_config()
    proxy = client.session(conf['blockstored_server'], conf['blockstored_port'])
    
    # do all registers
    for name in names:
        
        username = name['username']
        nmc_address = str(name['nmc_address'])
        update_hash = str(name['hash'])
        
        fqn = username + "." + namespace_id
        
        address = namecoin_to_bitcoin_address( nmc_address )
        
        if fqn in imported_names.keys():
            continue 

        print "name_import" + fqn + " " + address + " " + update_hash

        try:
            result = client.name_import( fqn, address, update_hash, privkey_str )
        except:
            traceback.print_exc()
            print >> sys.stderr, "register '%s' failed:\n%s\n" % (fqn, traceback.format_exc())
            
            failed.append( fqn )
            failed_fd.write( "%s\n" % (fqn))
            failed_fd.flush()
            continue 
        
        if type(result) == type([]):
            result = result[0]
        
        if 'error' in result.keys():
            print >> sys.stderr, "register '%s' failed:\n%s\n" % (fqn, pp.pformat(result))
            print >> sys.stderr, pretty_dump( result )
            
            failed.append( fqn )
            failed_fd.write( "%s\n" % (fqn))
            failed_fd.flush()
            continue 
        
        # record progress
        processed_so_far.append( fqn )
        
        result['name'] = fqn
        result_str = json.dumps( result )
        
        log_fd.write( "%s\n" % result_str)
        log_fd.flush()
        
        print pretty_dump( result )
        
        time.sleep(20)
        
        if (len(processed_so_far) % 20 == 0):
            
            checkpoint_tx = send_checkpoint( chaincom_client, privkey_str )
            print pretty_dump( checkpoint_tx )
            
            time.sleep(20)
            

    sys.exit(0)
        
