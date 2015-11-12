#!/usr/bin/env python 

import os
import sys 
import shutil

# hack around absolute paths 
current_dir =  os.path.abspath(os.path.dirname(__file__) + "/../..")
sys.path.insert(0, current_dir)

import pybitcoin
from blockstore.lib import *
from blockstore.tests import *
import virtualchain 
import importlib
import traceback

from blockstore.lib import nameset as blockstore_state_engine

import blockstore.tests.mock_bitcoind as mock_bitcoind

import blockstore
import blockstore.blockstored as blockstored
from blockstore.blockstored import get_state_engine

import scenarios.testlib as testlib

if not globals().has_key('log'):
    log = virtualchain.session.log

mock_bitcoind_connection = None

def load_scenario( scenario_name ):
    """
    Load up a scenario, and validate it.
    A scenario is a python file with:
    * a global variable 'wallet' that is a dict
    which maps private keys to their initial values.
    * a global variable 'consensus' that represents 
    the initial consensus hash.
    * a callable called 'scenario' that takes the 
    wallet as an argument and runs the test.
    * a callable called 'check' that takes the state 
    engine as an argument and checks it for correctness.
    """

    # strip .py from scenario name 
    if scenario_name.endswith(".py"):
        scenario_name = scenario_name[:-3]

    try:
        scenario = importlib.import_module( scenario_name )
    except ImportError, ie:
        raise Exception("Failed to import '%s'." % scenario_name )

    # validate 
    if not hasattr( scenario, "wallets" ):
        # default empty wallet 
        log.warning("Empty wallet for scenario '%s'" % scenario_name )
        scenario.wallets = {}

    if not hasattr( scenario, "consensus" ):
        # default consensus hash 
        log.warning("No consensus hash for '%s'" % scenario_name )
        scenario.consensus = "00" * 16

    if not hasattr( scenario, "scenario" ):
        # not a valid test 
        log.error("Invalid scenario '%s': no 'scenario' method" % scenario_name )
        return None 

    if not hasattr( scenario, "check" ):
        # not a valid test 
        log.error("Invalid scenario '%s': no 'check' method" % scenario_name )
        return None 

    return scenario
   

def write_config_file( scenario, path ):
    """
    Generate the config file to use with this test scenario.
    Write it to path.
    """

    initial_utxo_str = ",".join( ["%s:%s" % (w.privkey, w.value) for w in scenario.wallets] )
    config_file_in = "blockstore.ini.in"

    config_txt = None
    with open( config_file_in, "r" ) as f:
        config_txt = f.read()
        config_txt = config_txt.replace( "@MOCK_INITIAL_UTXOS@", initial_utxo_str )

    with open( path, "w" ) as f:
        f.write( config_txt )
        f.flush()

    return 0


def run_scenario( scenario, config_file ):
    """
    Run a test scenario:
    * set up the virtualchain to use our mock UTXO provider and mock bitcoin blockchain
    * seed it with the initial values in the wallet 
    * set the initial consensus hash 
    * run the scenario method
    * run the check method
    """

    # use mock bitcoind
    virtualchain.setup_virtualchain( blockstore_state_engine, bitcoind_connection_factory=mock_bitcoind.connect_mock_bitcoind ) 

    # set up blockstore
    # NOTE: utxo_opts encodes the mock-bitcoind options 
    blockstore_opts, bitcoin_opts, utxo_opts, dht_opts = blockstore.lib.configure( config_file=config_file, interactive=False )
   
    # override multiprocessing options to ensure single-process behavior 
    utxo_opts['multiprocessing_num_procs'] = 1 
    utxo_opts['multiprocessing_num_blocks'] = 64

    blockstored.set_bitcoin_opts( bitcoin_opts )
    blockstored.set_utxo_opts( utxo_opts )

    db = blockstored.get_state_engine()
    bitcoind = mock_bitcoind.connect_mock_bitcoind( utxo_opts )
    sync_virtualchain_upcall = lambda: virtualchain.sync_virtualchain( utxo_opts, bitcoind.getblockcount(), db )
    mock_utxo = blockstore.lib.connect_utxo_provider( utxo_opts )
    working_dir = virtualchain.get_working_dir()
 
    # set up test environment
    testlib.set_utxo_client( mock_utxo )
    testlib.set_bitcoind( bitcoind )
    testlib.set_state_engine( db )

    test_env = {
        "sync_virtualchain_upcall": sync_virtualchain_upcall,
        "working_dir": working_dir
    }

    # sync initial utxos 
    testlib.next_block( **test_env )

    # load the scenario into the mock blockchain and mock utxo provider
    try:
        scenario.scenario( scenario.wallets, **test_env )

    except Exception, e:
        log.exception(e)
        traceback.print_exc()
        log.error("Failed to run scenario '%s'" % scenario.__name__)
        return False

    # run the checks on the database
    try:
        rc = scenario.check( db )
    except Exception, e:
        log.exception(e)
        traceback.print_exc()
        log.error("Failed to run tests '%s'" % scenario.__name__)
        return False 
    
    if not rc:
        return rc

    log.info("Scenario checks passed; verifying history")

    # run database integrity check at each block 
    rc = testlib.check_history( db )
    if rc:
        testlib.cleanup()
    return rc 


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s [scenario.import.path] [OPTIONAL: working dir]"
        sys.exit(1)
 
    # load up the scenario 
    scenario = load_scenario( sys.argv[1] )
    if scenario is None:
        print "Failed to load '%s'" % sys.argv[1]
        sys.exit(1)

    working_dir = None
    if len(sys.argv) > 2:
        working_dir = sys.argv[2]
    else:
        working_dir = "/tmp/blockstore-run-scenario.%s" % scenario.__name__

    # patch state engine implementation
    blockstore_state_engine.working_dir = working_dir
    if not os.path.exists( blockstore_state_engine.working_dir ):
        os.makedirs( blockstore_state_engine.working_dir )

    # generate config file
    config_file = os.path.join( blockstore_state_engine.working_dir, "blockstore.ini" ) 
    rc = write_config_file( scenario, config_file )
    if rc != 0:
        log.error("failed to write config file: exit %s" % rc)
        sys.exit(1)

    # run the test 
    rc = run_scenario( scenario, config_file )
   
    if rc:
        print "SUCCESS %s" % scenario.__name__
        shutil.rmtree( working_dir )
        sys.exit(0)
    else:
        print >> sys.stderr, "FAILURE %s" % scenario.__name__
        print >> sys.stderr, "Test output in %s" % working_dir
        sys.exit(1)

    
