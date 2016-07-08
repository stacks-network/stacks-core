# -*- coding: utf-8 -*-
"""
    Registrar
    ~~~~~
    :copyright: (c) 2014-2016 by Halfmoon Labs, Inc.
    :copyright: (c) 2016 blockstack.org
    :license: MIT, see LICENSE for more details.
"""


import sqlite3
import traceback
import os
import sys
import json

from ..config import DEFAULT_QUEUE_PATH, QUEUE_LENGTH_TO_MONITOR, PREORDER_MAX_CONFIRMATIONS, CONFIG_PATH
from ..proxy import get_default_proxy

from ..storage import hash_zonefile
from ..proxy import is_name_registered, is_name_owner, has_zonefile_hash
from .blockchain import get_block_height, get_tx_confirmations, is_tx_rejected, is_tx_accepted

QUEUE_SQL = """
CREATE TABLE entries( fqu STRING NOT NULL,
                      queue_id STRING NOT NULL,
                      tx_hash STRING NOT NULL,
                      data NOT NULL,
                      PRIMARY KEY(fqu,queue_id) );
"""


from ..utils import pretty_print as pprint

from ..config import QUEUE_LENGTH_TO_MONITOR, MAX_TX_CONFIRMATIONS
from ..config import get_logger

log = get_logger()

def queuedb_create( path ):
    """
    Create a sqlite3 db at the given path.
    Create all the tables and indexes we need.
    """

    global QUEUE_SQL

    if os.path.exists( path ):
        raise Exception("Database '%s' already exists" % path)

    lines = [l + ";" for l in QUEUE_SQL.split(";")]
    con = sqlite3.connect( path, isolation_level=None )

    for line in lines:
        con.execute(line)

    con.row_factory = queuedb_row_factory
    return con


def queuedb_open( path ):
    """
    Open a connection to our database 
    """
    if not os.path.exists( path ):
        con = queuedb_create( path )
    else:
        con = sqlite3.connect( path, isolation_level=None )
        con.row_factory = queuedb_row_factory
    return con


def queuedb_row_factory( cursor, row ):
    """
    Row factor to enforce some additional types:
    * force 'revoked' to be a bool
    """
    d = {}
    for idx, col in enumerate( cursor.description ):
        if col[0] == 'revoked':
            if row[idx] == 0:
                d[col[0]] = False
            elif row[idx] == 1:
                d[col[0]] = True
            else:
                raise Exception("Invalid value for 'revoked': %s" % row[idx])

        else:
            d[col[0]] = row[idx]

    return d


def queuedb_query_execute( cur, query, values ):
    """
    Execute a query.  If it fails, exit.

    DO NOT CALL THIS DIRECTLY.
    """

    try:
        ret = cur.execute( query, values )
        return ret
    except Exception, e:
        log.exception(e)
        log.error("FATAL: failed to execute query (%s, %s)" % (query, values))
        log.error("\n".join(traceback.format_stack()))
        sys.exit(1)


def queuedb_find( queue_id, fqu, limit=None, path=DEFAULT_QUEUE_PATH ):
    """
    Find a record by fqu and queue ID
    Return the rows on success (empty list if not found)
    Raise on error
    """
    sql = "SELECT * FROM entries WHERE queue_id = ? AND fqu = ?;"
    args = (queue_id,fqu)
    
    db = queuedb_open(path)
    if db is None:
        raise Exception("Failed to open %s" % path)

    cur = db.cursor()
    rows = queuedb_query_execute( cur, sql, args )

    count = 0
    ret = []
    for row in rows:
        dat = {}
        dat.update(row)
        ret.append(dat)

        count += 1
        if limit is not None and count == limit:
            break

    db.commit()
    db.close()
    return ret


def queuedb_findall( queue_id, limit=None, path=DEFAULT_QUEUE_PATH ):
    """
    Get all queued entries
    Return the rows on success (empty list if not found)
    Raise on error
    """
    sql = "SELECT * FROM entries WHERE queue_id = ?;"
    args = (queue_id,)
    
    db = queuedb_open(path)
    if db is None:
        raise Exception("Failed to open %s" % path)

    cur = db.cursor()
    rows = queuedb_query_execute( cur, sql, args )

    count = 0
    ret = []
    for row in rows:
        dat = {}
        dat.update(row)
        ret.append(dat)

        count += 1
        if limit is not None and count == limit:
            break

    db.commit()
    db.close()
    return ret


def queuedb_insert( queue_id, fqu, tx_hash, data_json, path=DEFAULT_QUEUE_PATH ):
    """
    Insert an element into a queue
    Return True on success
    Raise on error
    """
    sql = "INSERT INTO entries VALUES (?,?,?,?);"
    args = (fqu, queue_id, tx_hash, json.dumps(data_json,sort_keys=True)) 

    db = queuedb_open(path)
    if db is None:
        raise Exception("Failed to open %s" % path)

    cur = db.cursor()
    res = queuedb_query_execute( cur, sql, args )

    db.commit()
    db.close()
    return True


def queuedb_remove( queue_id, fqu, tx_hash, path=DEFAULT_QUEUE_PATH ):
    """
    Remove an element from a queue.
    Return True on success
    Raise on error
    """
    sql = "DELETE FROM entries WHERE queue_id = ? AND fqu = ? AND tx_hash = ?;"
    args = (queue_id, fqu, tx_hash)

    db = queuedb_open(path)
    if db is None:
        raise Exception("Failed to open %s" % path)

    cur = db.cursor()
    res = queuedb_query_execute( cur, sql, args )

    db.commit()
    db.close()
    return True


def in_queue( queue_id, fqu, path=DEFAULT_QUEUE_PATH ):
    """
    Is this name already in the given queue?
    """
    res = queuedb_find( queue_id, fqu, limit=1, path=path )
    if len(res) > 0:
        return True
    else:
        return False


def queue_append(queue_id, fqu, tx_hash, payment_address=None,
                 owner_address=None, transfer_address=None,
                 config_path=CONFIG_PATH,
                 zonefile=None, profile=None, zonefile_hash=None, path=DEFAULT_QUEUE_PATH):

    """
    Append a processing name operation to the named queue for the given name.
    Return True on success
    Raise on error
    """
    new_entry = {}

    # required for all queues
    new_entry['payment_address'] = payment_address
    new_entry['block_height'] = get_block_height(config_path=config_path)

    # optional, depending on queue
    new_entry['owner_address'] = owner_address
    new_entry['transfer_address'] = transfer_address
    new_entry['zonefile'] = zonefile
    new_entry['profile'] = profile
    if zonefile_hash is None and zonefile is not None:
        zonefile_hash = hash_zonefile(zonefile)

    if zonefile_hash is not None:
        new_entry['zonefile_hash'] = zonefile_hash

    queuedb_insert( queue_id, fqu, tx_hash, new_entry, path=path )
    return True


def extract_entry( rowdata ):
    """
    Convert a row into a flat dict that contains everything.
    """
    entry = json.loads(rowdata['data'])
    entry['tx_hash'] = rowdata['tx_hash']
    entry['fqu'] = rowdata['fqu']
    entry['type'] = rowdata['queue_id']
    return entry


def is_entry_accepted( entry, config_path=CONFIG_PATH ):
    """
    Given a queue entry, determine if it was
    accepted onto the blockchain.
    Return True if so.
    Return False on error.
    """
    return is_tx_accepted( entry['tx_hash'], config_path=config_path )


def is_entry_rejected( entry, config_path=CONFIG_PATH ):
    """
    Given a queue entry, determine if it has 
    been pending for long enough that we can
    safely assume it won't be incorporated.
    """
    return is_tx_rejected( entry['tx_hash'], config_path=config_path )


def is_preorder_expired( entry, config_path=CONFIG_PATH ):
    """
    Given a preorder entry, determine whether or
    not it is expired
    """
    tx_confirmations = get_tx_confirmations(entry['tx_hash'], config_path=config_path)
    if tx_confirmations > PREORDER_MAX_CONFIRMATIONS:
        return True

    return False


def is_register_expired( entry, config_path=CONFIG_PATH ):
    """
    Is a registration expired?
    as in, is it older than its preorder?
    """
    return is_preorder_expired( entry, config_path=config_path )


def is_update_expired( entry, config_path=CONFIG_PATH ):
    """
    Is an update expired?
    """
    confirmations = get_tx_confirmations(entry['tx_hash'], config_path=config_path)
    if confirmations > MAX_TX_CONFIRMATIONS:
        return True

    return False


def is_transfer_expired( entry, config_path=CONFIG_PATH ):
    """
    Is a transfer expired?
    """
    return is_update_expired(entry, config_path=config_path)


def is_renew_expired( entry, config_path=CONFIG_PATH ):
    """
    Is a renew expired?
    """
    return is_update_expired(entry, config_path=config_path)


def is_revoke_expired( entry, config_path=CONFIG_PATH ):
    """
    Is a revoke expired?
    """
    return is_revoke_expired(entry, config_path=CONFIG_PATH)


def display_queue(queue_id, display_details=False, path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Print debugging information about a queue
    """
    track_confirmations = [0] * QUEUE_LENGTH_TO_MONITOR

    rows = queuedb_findall( queue_id, path=path)
    for rowdata in rows:
        entry = extract_entry(rowdata)

        try:
            confirmations = get_tx_confirmations(entry['tx_hash'], config_path=config_path)
        except:
            continue

        try:
            track_confirmations[confirmations] += 1
        except:
            pass

        if display_details:
            log.debug('-' * 5)
            log.debug("%s %s" % (queue.name, entry['fqu']))
            log.debug("(%s, confirmations %s)" % (entry['tx_hash'],
                                              confirmations))
            log.debug("payment: %s" % entry['payment_address'])
            log.debug("owner: %s" % entry['owner_address'])

            if entry['payment_address'] == entry['owner_address']:
                log.debug("problem")

    log.debug(queue.name)
    log.debug(track_confirmations)
    log.debug('-' * 5)


def cleanup_preorder_queue(path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Clear out the preorder queue.
    Remove rows that refer to registered names, or to stale preorders.
    Return True on success.
    Raise on error
    """
    rows = queuedb_findall("preorder", path=path)
    to_remove = []
    for rowdata in rows:
        entry = extract_entry(rowdata)

        # clear stale preorder
        if is_preorder_expired( entry, config_path=config_path ):
            log.debug("Removing stale preorder: %s" % entry['fqu'])
            to_remove.append(entry)
            continue

    queue_removeall( to_remove, path=path )
    return True


def cleanup_register_queue(path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Clear out the register queue.
    Remove rows that refer to registered names that have zonefile hashes, or to stale preorders.
    Return True on success
    Raise on error.
    """
    rows = queuedb_findall("register", path=path)
    to_remove = []
    for rowdata in rows:
        entry = extract_entry(rowdata)

        # clear stale register
        if is_register_expired( entry, config_path=config_path ):
            log.debug("Removing stale register: %s" % entry['fqu'])
            to_remove.append(entry)
            continue

    queue_removeall( to_remove, path=path )
    return True


def cleanup_update_queue(path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Clear out the update queue.
    Remove rows that refer to registered names, or to stale updates.
    Return True on success
    Raise on error.
    """
    rows = queuedb_findall("update", path=path)
    to_remove = []
    for rowdata in rows:
        entry = extract_entry(rowdata)
        
        # clear stale update
        if is_update_expired(entry, config_path=config_path):
            log.debug("Removing tx with > max confirmations: (%s, confirmations %s)"
                      % (fqu, confirmations))

            to_remove.append(entry)
            continue

    queue_removeall( to_remove, path=path )
    return True


def cleanup_transfer_queue(path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Clear out the transfer queue.
    Remove rows that refer to registered names, or to stale transfers.
    Return True on success
    Raise on error.
    """
    rows = queuedb_findall("transfer", path=path)
    to_remove = []
    for rowdata in rows:
        entry = extract_entry(rowdata)
        
        fqu = entry['fqu']
        try:
            transfer_address = entry['transfer_address']
        except:
            log.debug("Transfer address not saved")
            exit(0)

        # clear stale transfer
        if is_transfer_expired(entry, config_path=config_path):
            log.debug("Removing tx with > max confirmations: (%s, %s, confirmations %s)"
                      % (fqu, transfer_address, confirmations))

            to_remove.append(entry)
            continue

    queue_removeall( to_remove, path=path )
    return True


def cleanup_renew_queue(path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Clear out the renew queue.
    Remove rows that refer to renewed names, or stale renews.
    Return True on success
    Raise on error
    """
    rows = queuedb_findall("renew", path=path)
    to_remove = []
    for rowdata in rows:
        entry = extract_entry(rowdata)
        
        # clear stale renew
        if is_renew_expired(entry, config_path=config_path):
            log.debug("Removing tx with > max confirmations: (%s, confirmations %s)"
                      % (fqu, confirmations))

            to_remove.append(entry)
            continue

    queue_removeall( to_remove, path=path )
    return True


def cleanup_revoke_queue(path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Clear out the revoke queue.
    Remove rows that refer to revoked names, or stale revokes.
    Return True on success
    Raise on error
    """
    rows = queuedb_findall("revoke", path=path)
    to_remove = []
    for rowdata in rows:
        entry = extract_entry(rowdata)
        
        # clear stale renew
        if is_revoke_expired(entry, config_path=config_path):
            log.debug("Removing tx with > max confirmations: (%s, confirmations %s)"
                      % (fqu, confirmations))

            to_remove.append(entry)
            continue

    queue_removeall( to_remove, path=path )
    return True


def queue_cleanall(path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Clean all queues
    Return True on success
    Raise on error
    """

    cleanup_preorder_queue(path=path, config_path=config_path)
    cleanup_register_queue(path=path, config_path=config_path)
    cleanup_update_queue(path=path, config_path=config_path )
    cleanup_transfer_queue(path=path, config_path=config_path )
    cleanup_renew_queue(path=path, config_path=config_path)
    cleanup_revoke_queue(path=path, config_path=config_path)


def display_queue_info(display_details=False, path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Dump all information about our queues 
    to stderr.
    """
    display_queue("preorder", display_details, path=path, config_path=config_path)
    display_queue("register", display_details, path=path, config_path=config_path)
    display_queue("update", display_details, path=path, config_path=config_path)
    display_queue("transfer", display_details, path=path, config_path=config_path)
    display_queue("renew", display_details, path=path, config_path=config_path)
    display_queue("revoke", display_details, path=path, config_path=config_path)


def get_queue_state(queue_ids=None, path=DEFAULT_QUEUE_PATH):
    """
    Load one or more queue states into RAM.
    Return the appended list.
    """
    state = []
    if queue_ids is None:
        queue_ids = ["preorder", "register", "update", "transfer", "renew", "revoke"]

    elif type(queue_ids) not in [list]:
        queue_ids = [queue_ids]

    for queue_id in queue_ids:
        raw_rows = queuedb_findall( queue_id, path=path )
        rows = [extract_entry(r) for r in raw_rows]
        state += rows

    return state


def queue_findall( queue_id, path=DEFAULT_QUEUE_PATH ):
    """
    Load a single queue into RAM
    """
    return get_queue_state( queue_id, path=path )


def queue_remove_expired(queue_id, path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH):
    """
    Remove expired transactions
    from the given queue.
    Return True on success
    Raise on error
    """
    rows = queuedb_findall( queue_id, path=path )
    to_remove = []
    for rowdata in rows:
        entry = extract_entry(rowdata)
        if is_entry_rejected( entry, config_path=config_path ):
            log.debug("TX rejected by network, removing TX: %s" % entry['tx_hash'])
            to_remove.append(entry)

    queue_removeall( to_remove, path=path )
    return True


def queue_removeall( entries, path=DEFAULT_QUEUE_PATH ):
    """
    Remove all given entries form their given queues
    """
    for entry in entries:
        rc = queuedb_remove( entry['type'], entry['fqu'], entry['tx_hash'], path=path )
        if not rc:
            raise Exception("Failed to remove %s.%s.%s" % (entry['type'], entry['fqu'], entry['tx_hash']))

    return True


def queue_find_accepted( queue_id, path=DEFAULT_QUEUE_PATH, config_path=CONFIG_PATH ):
    """
    Find all pending operations in the given queue
    that have been accepted.
    """
    rows = queuedb_findall( queue_id, path=path )
    accepted = []
    for rowdata in rows:
        entry = extract_entry(rowdata)
        if is_entry_accepted( entry, config_path=config_path ):
            accepted.append(entry)

    return accepted


def queue_findone( queue_id, fqu, path=DEFAULT_QUEUE_PATH ):
    """
    Find one instance of a name
    """
    return queuedb_find( queue_id, fqu, limit=1, path=path )
