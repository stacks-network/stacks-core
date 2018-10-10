#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2018 by Blockstack.org

    This file is part of Blockstack

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

import sqlite3
import subprocess
import json
import simplejson
import traceback
import os
import sys
import copy
import time
import random

# hack around absolute paths
curr_dir = os.path.abspath( os.path.join( os.path.dirname(__file__), ".." ) )
sys.path.insert( 0, curr_dir )

from ..config import * 
from ..operations import *
from ..hashing import *
from ..scripts import *
from ..b40 import *
from ..util import db_query_execute, db_format_query

import virtualchain

log = virtualchain.get_logger("blockstack-server")

BLOCKSTACK_DB_SCRIPT = ""

BLOCKSTACK_DB_SCRIPT += """
-- Blockchain history table---stores points in time at which every *on-chain* operation occurs.
-- NOTE: history_id is a fully-qualified name or namespace ID.
-- NOTE: creator_address is the address that owned the name or namespace ID at the time of insertion
-- NOTE: value_hash is the associated value hash for this history entry at the time of insertion.
-- NOTE: history_data is a JSON blob with the operation that was committed at this point in time.
CREATE TABLE history( txid TEXT NOT NULL,
                      history_id STRING,
                      creator_address STRING,
                      block_id INT NOT NULL,
                      vtxindex INT NOT NULL,
                      op TEXT NOT NULL,
                      opcode TEXT NOT NULL,
                      value_hash TEXT,
                      history_data TEXT NOT NULL,
                      PRIMARY KEY(txid,block_id,vtxindex) );
"""

BLOCKSTACK_DB_SCRIPT += """
-- CREATE INDEX history_block_id_index ON history( history_id, block_id );
CREATE INDEX history_id_index ON history( history_id );
"""

BLOCKSTACK_DB_SCRIPT += """
-- NOTE: this table only grows.
-- The only time rows can be taken out is when a name or
-- namespace successfully matches it.
CREATE TABLE preorders( preorder_hash TEXT NOT NULL,
                        consensus_hash TEXT NOT NULL,
                        sender TEXT NOT NULL,
                        sender_pubkey TEXT,
                        address TEXT,
                        block_number INT NOT NULL,
                        op TEXT NOT NULL,
                        op_fee INT NOT NULL,
                        txid TEXT NOT NULL,
                        vtxindex INT,
                        burn_address TEXT NOT NULL,

                        -- primary key includes the block number and txid, so an expired preorder can be overwritten
                        PRIMARY KEY(preorder_hash,block_number,txid));
"""

BLOCKSTACK_DB_SCRIPT += """
-- NOTE: this table includes revealed namespaces
-- NOTE: 'buckets' is a string representation of an array of 16 integers.
CREATE TABLE namespaces( namespace_id STRING NOT NULL,
                         preorder_hash TEXT NOT NULL,
                         version INT,
                         sender TEXT NOT NULL,
                         sender_pubkey TEXT,
                         address TEXT,
                         recipient TEXT NOT NULL,
                         recipient_address TEXT,
                         block_number INT NOT NULL,
                         reveal_block INT NOT NULL,
                         op TEXT NOT NULL,
                         op_fee INT NOT NULL,
                         txid TEXT NOT NULL NOT NULL,
                         vtxindex INT NOT NULL,
                         lifetime INT NOT NULL,
                         coeff INT NOT NULL,
                         base INT NOT NULL,
                         buckets TEXT NOT NULL,
                         nonalpha_discount INT NOT NULL, 
                         no_vowel_discount INT NOT NULL,
                         ready_block INT NOT NULL,

                         -- primary key includes block number, so an expired revealed namespace can be re-revealed
                         PRIMARY KEY(namespace_id,block_number)
                         );
"""

BLOCKSTACK_DB_SCRIPT += """
CREATE TABLE name_records( name STRING NOT NULL,
                           preorder_hash TEXT NOT NULL,
                           name_hash128 TEXT NOT NULL,
                           namespace_id STRING NOT NULL,
                           namespace_block_number INT NOT NULL,
                           value_hash TEXT,
                           sender TEXT NOT NULL,
                           sender_pubkey TEXT,
                           address TEXT,
                           block_number INT NOT NULL,
                           preorder_block_number INT NOT NULL,
                           first_registered INT NOT NULL,
                           last_renewed INT NOT NULL,
                           revoked INT NOT NULL,
                           op TEXT NOT NULL,
                           txid TEXT NOT NULL,
                           vtxindex INT NOT NULL,
                           op_fee INT NOT NULL,
                           importer TEXT,
                           importer_address TEXT,
                           consensus_hash TEXT,

                           -- for compatibility with previous versions' quirks
                           last_creation_op STRING NOT NULL,

                           -- primary key includes block number, so an expired name can be re-registered 
                           PRIMARY KEY(name,block_number),

                           -- namespace must exist
                           FOREIGN KEY(namespace_id,namespace_block_number) REFERENCES namespaces(namespace_id,block_number)
                           );
"""

BLOCKSTACK_DB_SCRIPT += """
CREATE INDEX hash_names_index ON name_records( name_hash128, name );
"""

BLOCKSTACK_DB_SCRIPT += """
CREATE INDEX value_hash_names_index on name_records( value_hash, name );
"""

BLOCKSTACK_DB_SCRIPT += """
CREATE INDEX addr_names_index ON name_records( address, name );
"""

BLOCKSTACK_DB_SCRIPT += """
-- turn on foreign key constraints 
PRAGMA foreign_keys = ON;
"""


def namedb_create( path ):
    """
    Create a sqlite3 db at the given path.
    Create all the tables and indexes we need.
    """

    global BLOCKSTACK_DB_SCRIPT

    if os.path.exists( path ):
        raise Exception("Database '%s' already exists" % path)

    lines = [l + ";" for l in BLOCKSTACK_DB_SCRIPT.split(";")]
    con = sqlite3.connect( path, isolation_level=None, timeout=2**30 )

    for line in lines:
        db_query_execute(con, line, ())

    con.row_factory = namedb_row_factory
    return con


def namedb_open( path ):
    """
    Open a connection to our database 
    """
    con = sqlite3.connect( path, isolation_level=None, timeout=2**30 )
    con.row_factory = namedb_row_factory
    return con


def namedb_row_factory( cursor, row ):
    """
    Row factor to enforce some additional types:
    * force 'revoked' to be a bool
    """
    d = {}
    for idx, col in enumerate( cursor.description ):
        if col[0] in ['revoked']:
            if row[idx] == 0:
                d[col[0]] = False
            elif row[idx] == 1:
                d[col[0]] = True
            elif row[idx] is None:
                d[col[0]] = None
            else:
                raise Exception("Invalid value for 'revoked': %s" % row[idx])

        else:
            d[col[0]] = row[idx]

    return d


def namedb_get_namespace_lifetime_multiplier( block_height, namespace_id ):
    """
    User-defined sqlite3 function that gets the namespace
    lifetime multiplier at a particular block height.

    OBSOLETE
    """
    try:
        namespace_lifetime_multiplier = get_epoch_namespace_lifetime_multiplier( block_height, namespace_id )
        return namespace_lifetime_multiplier
    except Exception, e:
        try:
            with open("/tmp/blockstack_db_exception.txt", "w") as f:
                f.write(traceback.format_exc())
        except:
            raise

        raise


def namedb_get_namespace_lifetime_grace_period( block_height, namespace_id ):
    """
    User-defined sqlite3 function that gets the namespace
    lifetime grace period at a particular block height.

    OBSOLETE
    """
    try:
        namespace_lifetime_grace_period = get_epoch_namespace_lifetime_grace_period( block_height, namespace_id )
        return namespace_lifetime_grace_period
    except Exception, e:
        try:
            with open("/tmp/blockstack_db_exception.txt", "w") as f:
                f.write(traceback.format_exc())
        except:
            raise

        raise


def namedb_find_missing_and_extra(cur, record, table_name):
    """
    Find the set of fields missing from record, and set of extra fields from record, based on the db schema.
    Return (missing, extra)
    """
    rec_missing = []
    rec_extra = []
    
    # sanity check: all fields must be defined
    name_fields_rows = db_query_execute(cur, 'PRAGMA table_info({})'.format(table_name), ())
    name_fields = []
    for row in name_fields_rows:
        name_fields.append( row['name'] )

    # make sure each column has a record field
    for f in name_fields:
        if f not in record.keys():
            rec_missing.append( f )

    # make sure each record field has a column
    for k in record.keys():
        if k not in name_fields:
            rec_extra.append( k )

    return rec_missing, rec_extra


def namedb_assert_fields_match( cur, record, table_name, record_matches_columns=True, columns_match_record=True ):
    """
    Ensure that the fields of a given record match
    the columns of the given table.
    * if record_match_columns, then the keys in record must match all columns.
    * if columns_match_record, then the columns must match the keys in the record.

    Return True if so.
    Raise an exception if not.
    """
    rec_missing, rec_extra = namedb_find_missing_and_extra(cur, record, table_name)
    if (len(rec_missing) > 0 and columns_match_record) or (len(rec_extra) > 0 and record_matches_columns):
        raise Exception("Invalid record: missing = %s, extra = %s" % 
                        (",".join(rec_missing), ",".join(rec_extra)))

    return True


def namedb_insert_prepare( cur, record, table_name ):
    """
    Prepare to insert a record, but make sure
    that all of the column names have values first!

    Return an INSERT INTO statement on success.
    Raise an exception if not.
    """

    namedb_assert_fields_match( cur, record, table_name )
     
    columns = record.keys()
    columns.sort()

    values = []
    for c in columns:
        if record[c] == False:
            values.append(0)
        elif record[c] == True:
            values.append(1)
        else:
            values.append(record[c])
    
    values = tuple(values)

    field_placeholders = ",".join( ["?"] * len(columns) )

    query = "INSERT INTO %s (%s) VALUES (%s);" % (table_name, ",".join(columns), field_placeholders)
    log.debug(namedb_format_query(query, values))

    return (query, values)


def namedb_update_prepare( cur, primary_key_or_keys, input_record, table_name, must_equal=[], only_if={} ):
    """
    Prepare to update a record, but make sure that the fields in input_record
    correspond to acual columns.
    Also, enforce any fields that must be equal to the fields
    in the given record (must_equal), and require that certian fields in record
    have certain values first (only_if)

    Return an UPDATE ... SET ... WHERE statement on success.
    Raise an exception if not.

    DO NOT CALL THIS METHOD DIRECTLY
    """

    record = copy.deepcopy( input_record )
    must_equal_dict = dict( [(c, None) for c in must_equal] )

    # extract primary key
    # sanity check: primary key cannot be mutated
    primary_keys = []
    if isinstance(primary_key_or_keys, (str,unicode)):
        primary_keys = [primary_key_or_keys]
    else:
        primary_keys = primary_key_or_keys

    for primary_key_col in primary_keys:
        primary_key_value = record.get(primary_key_col, None)
        assert primary_key_value is not None, "BUG: no primary key value given in record"
        assert primary_key_col in must_equal, "BUG: primary key set to change"

    assert len(must_equal) > 0, "BUG: no identifying information for this record"

    # find set of columns that will change 
    update_columns = []
    for k in input_record.keys():
        if k not in must_equal:
            update_columns.append( k )

    # record keys correspond to real columns
    namedb_assert_fields_match( cur, record, table_name, columns_match_record=False )

    # must_equal keys correspond to real columns
    namedb_assert_fields_match( cur, must_equal_dict, table_name, columns_match_record=False )

    # only_if keys correspond to real columns 
    namedb_assert_fields_match( cur, only_if, table_name, columns_match_record=False )

    # only_if does not overlap with must_equal
    assert len( set(must_equal).intersection(only_if.keys()) ) == 0, "BUG: only_if and must_equal overlap"

    update_values = []
    for c in update_columns:
        if record[c] == False:
            update_values.append(0)
        elif record[c] == True:
            update_values.append(1)
        else:
            update_values.append(record[c])

    update_values = tuple(update_values)
    update_set = [("%s = ?" % c) for c in update_columns]

    where_set = []
    where_values = []
    for c in must_equal:
        if record[c] is None:
            where_set.append( "%s IS NULL" % c )
        elif record[c] == True:
            where_set.append( "%s = 1" % c )
        elif record[c] == False:
            where_set.append( "%s = 0" % c )
        else:
            where_set.append( "%s = ?" % c)
            where_values.append( record[c] )


    for c in only_if.keys():
        if only_if[c] is None:
            where_set.append( "%s IS NULL" % c)
        elif record[c] == True:
            where_set.append( "%s = 1" % c )
        elif record[c] == False:
            where_set.append( "%s = 0" % c )
        else:
            where_set.append( "%s = ?" % c)
            where_values.append( only_if[c] )

    where_values = tuple(where_values)

    query = "UPDATE %s SET %s WHERE %s" % (table_name, ", ".join(update_set), " AND ".join(where_set))

    log.debug(namedb_format_query(query, update_values + where_values))

    return (query, update_values + where_values)


def namedb_update_must_equal( rec, change_fields ):
    """
    Generate the set of fields that must stay the same across an update.
    """
    
    must_equal = []
    if len(change_fields) != 0:
        given = rec.keys()
        for k in given:
            if k not in change_fields:
                must_equal.append(k)

    return must_equal


def namedb_delete_prepare( cur, primary_key, primary_key_value, table_name ):
    """
    Prepare to delete a record, but make sure the fields in record
    correspond to actual columns.
    
    Return a DELETE FROM ... WHERE statement on success.
    Raise an Exception if not.

    DO NOT CALL THIS METHOD DIRETLY
    """
    # primary key corresponds to a real column 
    namedb_assert_fields_match( cur, {primary_key: primary_key_value}, table_name, columns_match_record=False )

    query = "DELETE FROM %s WHERE %s = ?;" % (table_name, primary_key)
    values = (primary_key_value,)
    return (query, values)


def namedb_format_query( query, values ):
    """
    Turn a query into a string for printing.
    Useful for debugging.
    """
    return db_format_query(query, values)


def namedb_query_execute( cur, query, values ):
    """
    Execute a query.  If it fails, abort.  Retry with timeouts on lock

    DO NOT CALL THIS DIRECTLY.
    """
    return db_query_execute(cur, query, values)


def namedb_preorder_insert( cur, preorder_rec ):
    """
    Add a name or namespace preorder record, if it doesn't exist already.

    DO NOT CALL THIS DIRECTLY.
    """

    preorder_row = copy.deepcopy( preorder_rec )
    
    assert 'preorder_hash' in preorder_row, "BUG: missing preorder_hash"

    try:
        preorder_query, preorder_values = namedb_insert_prepare( cur, preorder_row, "preorders" )
    except Exception, e:
        log.exception(e)
        log.error("FATAL: Failed to insert name preorder '%s'" % preorder_row['preorder_hash']) 
        os.abort()

    namedb_query_execute( cur, preorder_query, preorder_values )
    return True


def namedb_preorder_remove( cur, preorder_hash ):
    """
    Remove a preorder hash.

    DO NOT CALL THIS DIRECTLY.
    """
    try:
        query, values = namedb_delete_prepare( cur, 'preorder_hash', preorder_hash, 'preorders' )
    except Exception, e:
        log.exception(e)
        log.error("FATAL: Failed to delete preorder with hash '%s'" % preorder_hash )
        os.abort()

    log.debug(namedb_format_query(query, values))
    namedb_query_execute( cur, query, values )
    return True


def namedb_name_fields_check( name_rec ):
    """
    Make sure that a name record has some fields
    that must always be present:
    * name
    * namespace_id
    * name_hash128

    Makes the record suitable for insertion/update.
    NOTE: MODIFIES name_rec
    """

    if not name_rec.has_key('name'):
        raise Exception("BUG: name record has no name")

    # extract namespace ID if it's not already there 
    if not name_rec.has_key('namespace_id'):
        name_rec['namespace_id'] = get_namespace_from_name( name_rec['name'] )

    # extract name_hash if it's not already there 
    if not name_rec.has_key('name_hash128'):
        name_rec['name_hash128'] = hash256_trunc128( name_rec['name'] )

    return True


def namedb_name_insert( cur, input_name_rec ):
    """
    Add the given name record to the database,
    if it doesn't exist already.
    """
   
    name_rec = copy.deepcopy( input_name_rec )
    namedb_name_fields_check( name_rec )

    try:
        query, values = namedb_insert_prepare( cur, name_rec, "name_records" )
    except Exception, e:
        log.exception(e)
        log.error("FATAL: Failed to insert name '%s'" % name_rec['name'])
        os.abort()

    namedb_query_execute( cur, query, values )

    return True


def namedb_name_update( cur, opcode, input_opdata, only_if={}, constraints_ignored=[] ):
    """
    Update an existing name in the database.
    If non-empty, only update the given fields.

    DO NOT CALL THIS METHOD DIRECTLY.
    """

    opdata = copy.deepcopy( input_opdata )
    namedb_name_fields_check( opdata )
    mutate_fields = op_get_mutate_fields( opcode )

    if opcode not in OPCODE_CREATION_OPS:
        assert 'name' not in mutate_fields, "BUG: 'name' listed as a mutate field for '%s'" % (opcode)

    # reduce opdata down to the given fields....
    must_equal = namedb_update_must_equal( opdata, mutate_fields )
    must_equal += ['name','block_number']

    for ignored in constraints_ignored:
        if ignored in must_equal:
            # ignore this constraint 
            must_equal.remove( ignored )

    try:
        query, values = namedb_update_prepare( cur, ['name', 'block_number'], opdata, "name_records", must_equal=must_equal, only_if=only_if )
    except Exception, e:
        log.exception(e)
        log.error("FATAL: failed to update name '%s'" % opdata['name'])
        os.abort()

    namedb_query_execute( cur, query, values )

    try:
        assert cur.rowcount == 1, "Updated %s row(s)" % cur.rowcount 
    except Exception, e:
        log.exception(e)
        log.error("FATAL: failed to update name '%s'" % opdata['name'])
        log.error("Query: %s", "".join( ["%s %s" % (frag, "'%s'" % val if type(val) in [str, unicode] else val) for (frag, val) in zip(query.split("?"), values + ("",))] ))
        os.abort()

    return True


def namedb_namespace_fields_check( namespace_rec ):
    """
    Given a namespace record, make sure the following fields are present:
    * namespace_id
    * buckets

    Makes the record suitable for insertion/update.
    NOTE: MODIFIES namespace_rec
    """

    assert namespace_rec.has_key('namespace_id'), "BUG: namespace record has no ID"
    assert namespace_rec.has_key('buckets'), 'BUG: missing price buckets'
    assert isinstance(namespace_rec['buckets'], str), 'BUG: namespace data is not in canonical form'

    return namespace_rec


def namedb_namespace_insert( cur, input_namespace_rec ):
    """
    Add a namespace to the database,
    if it doesn't exist already.
    It must be a *revealed* namespace, not a ready namespace
    (to mark a namespace as ready, you should use the namedb_apply_operation()
    method).
    """

    namespace_rec = copy.deepcopy( input_namespace_rec )

    namedb_namespace_fields_check( namespace_rec )

    try:
        query, values = namedb_insert_prepare( cur, namespace_rec, "namespaces" )
    except Exception, e:
        log.exception(e)
        log.error("FATAL: Failed to insert revealed namespace '%s'" % namespace_rec['namespace_id']) 
        os.abort()

    namedb_query_execute( cur, query, values )
    return True


def namedb_namespace_update( cur, opcode, input_opdata, only_if={}, constraints_ignored=[] ):
    """
    Make a namespace ready.
    Only works if the namespace is *not* ready.

    DO NOT CALL THIS METHOD DIRECTLY.
    """

    opdata = copy.deepcopy( input_opdata )
    assert opdata.has_key('namespace_id'), "BUG: namespace record has no ID"

    mutate_fields = op_get_mutate_fields( opcode ) 
    
    if opcode not in OPCODE_CREATION_OPS:
        assert 'namespace_id' not in mutate_fields, "BUG: 'namespace_id' listed as a mutate field for '%s'" % (opcode)

    else:
        namedb_namespace_fields_check( opdata )

    # reduce opdata down to the given fields....
    must_equal = namedb_update_must_equal( opdata, mutate_fields )
    must_equal += ['namespace_id','block_number']
 
    for ignored in constraints_ignored:
        if ignored in must_equal:
            # ignore this constraint 
            must_equal.remove( ignored )

    try:
        query, values = namedb_update_prepare( cur, ['namespace_id', 'block_number'], opdata, "namespaces", must_equal=must_equal, only_if={} )
    except Exception, e:
        log.exception(e)
        log.error("FATAL: failed to update name '%s'" % opdata['namespace_id'])
        os.abort()

    namedb_query_execute( cur, query, values )

    try:
        assert cur.rowcount == 1, "Updated %s row(s)" % cur.rowcount 
    except Exception, e:
        log.exception(e)
        log.error("FATAL: failed to update name '%s'" % opdata['namespace_id'])
        log.error("Query: %s", "".join( ["%s %s" % (frag, "'%s'" % val if type(val) in [str, unicode] else val) for (frag, val) in zip(query.split("?"), values + ("",))] ))
        os.abort()

    return True
    

def namedb_op_sanity_check( opcode, op_data, record ):
    """
    Sanity checks over operation and state graph data:
    * opcode and op_data must be consistent
    * record must have an opcode
    * the given opcode must be reachable from it.
    """

    assert 'address' in record, "BUG: current record has no 'address' field"

    assert op_data.has_key('op'), "BUG: operation data is missing its 'op'"
    op_data_opcode = op_get_opcode_name( op_data['op'] )

    assert record.has_key('op'), "BUG: current record is missing its 'op'"
    cur_opcode = op_get_opcode_name( record['op'] )

    assert op_data_opcode is not None, "BUG: undefined operation '%s'" % op_data['op']
    assert cur_opcode is not None, "BUG: undefined current operation '%s'" % record['op']

    if op_data_opcode != opcode:
        # only allowed of the serialized opcode is the same
        # (i.e. as is the case for register/renew)
        assert NAME_OPCODES.get( op_data_opcode, None ) is not None, "BUG: unrecognized opcode '%s'" % op_data_opcode
        assert NAME_OPCODES.get( opcode, None ) is not None, "BUG: unrecognized opcode '%s'" % opcode 

        assert NAME_OPCODES[op_data_opcode] == NAME_OPCODES[opcode], "BUG: %s != %s" % (opcode, op_data_opcode)

    assert opcode in OPCODE_SEQUENCE_GRAPH, "BUG: impossible to arrive at operation '%s'" % opcode
    assert cur_opcode in OPCODE_SEQUENCE_GRAPH, "BUG: impossible to have processed operation '%s'" % cur_opcode
    assert opcode in OPCODE_SEQUENCE_GRAPH[ cur_opcode ], "BUG: impossible sequence from '%s' to '%s'" % (cur_opcode, opcode)

    return True


def namedb_state_mutation_sanity_check( opcode, op_data ):
    """
    Make sure all mutate fields for this operation are present.
    Return True if so
    Raise exception if not
    """

    # sanity check:  each mutate field in the operation must be defined in op_data, even if it's null.
    missing = []
    mutate_fields = op_get_mutate_fields( opcode )
    for field in mutate_fields:
        if field not in op_data.keys():
            missing.append( field )

    assert len(missing) == 0, ("BUG: operation '%s' is missing the following fields: %s" % (opcode, ",".join(missing)))
    return True


def namedb_state_transition_sanity_check( opcode, op_data, history_id, cur_record, record_table ):
    """
    Sanity checks: make sure that:
    * the opcode and op_data are consistent with one another.
    * the history_id, cur_record, and record_table are consistent with one another.

    Return True if so.
    Raise an exception if not.

    DO NOT CALL THIS METHOD DIRECTLY.
    """

    namedb_op_sanity_check( opcode, op_data, cur_record )

    if opcode in OPCODE_NAME_STATE_TRANSITIONS:
        # name state transition 
        assert record_table == "name_records", "BUG: name state transition opcode (%s) on table %s" % (opcode, record_table)
        assert cur_record.has_key('name'), "BUG: name state transition with no name"
        assert op_data.has_key('name'), "BUG: name state transition with no name"
        assert op_data['name'] == history_id, 'BUG: name op data is for the wrong name ({} != {})'.format(op_data['name'], history_id)
        assert op_data['name'] == cur_record['name'], 'BUG: name op data is for the wrong name ({} != {})'.format(op_data['name'], cur_record['name'])
        assert cur_record['name'] == history_id, "BUG: history ID '%s' != '%s'" % (history_id, cur_record['name'])

    elif opcode in OPCODE_NAMESPACE_STATE_TRANSITIONS:
        # namespace state transition 
        assert record_table == "namespaces", "BUG: namespace state transition opcode (%s) on table %s" % (opcode, record_table)
        assert cur_record.has_key('namespace_id'), "BUG: namespace state transition with no namespace ID"
        assert cur_record['namespace_id'] == history_id, "BUG: history ID '%s' != '%s'" % (history_id, cur_record['namespace_id'])
        assert op_data['namespace_id'] == history_id, 'BUG: name op data is for the wrong name ({} != {})'.format(op_data['namespace_id'], history_id)
        assert op_data['namespace_id'] == cur_record['namespace_id'], 'BUG: name op data is for the wrong name ({} != {})'.format(op_data['namespace_id'], cur_record['namespace_id'])
        assert cur_record['namespace_id'] == history_id, "BUG: history ID '%s' != '%s'" % (history_id, cur_record['namespace_id'])

    assert cur_record.has_key('block_number'), 'BUG: name state transition with no block number'
    if op_data.has_key('block_number'):
        assert op_data['block_number'] == cur_record['block_number'], 'BUG: block number mismatch ({} != {})'.format(op_data['block_number'], cur_record['block_number'])

    return True


def namedb_state_transition( cur, opcode, op_data, block_id, vtxindex, txid, history_id, cur_record, record_table, constraints_ignored=[] ):
    """
    Given an operation (opcode, op_data), a point in time (block_id, vtxindex, txid), and a current
    record (history_id, cur_record), apply the operation to the record and save the delta to the record's
    history.  Also, insert or update the new record into the db.

    The cur_record must exist already.

    Return the newly updated record on success, with all compatibility quirks preserved.
    Raise an exception on failure.

    DO NOT CALL THIS METHOD DIRECTLY.
    """
    
    # sanity check: must be a state-transitioning operation
    try:
        assert opcode in OPCODE_NAME_STATE_TRANSITIONS + OPCODE_NAMESPACE_STATE_TRANSITIONS, "BUG: opcode '%s' is not a state-transition"
        assert 'opcode' not in op_data, 'BUG: opcode not allowed in op_data'
    except Exception, e:
        log.exception(e)
        log.error("BUG: opcode '%s' is not a state-transition operation" % opcode)
        os.abort()

    # make sure we have a name/namespace_id and block number
    op_data_name = copy.deepcopy(op_data)

    if opcode in OPCODE_NAME_STATE_TRANSITIONS:
        # name state transition 
        op_data_name['name'] = history_id

    elif opcode in OPCODE_NAMESPACE_STATE_TRANSITIONS:
        # namespace state transition 
        op_data_name['namespace_id'] = history_id

    # sanity check make sure we got valid state transition data
    try:
        assert cur_record.has_key('block_number'), 'current record does not have a block number'
        op_data_name['block_number'] = cur_record['block_number']

        rc = namedb_state_transition_sanity_check( opcode, op_data_name, history_id, cur_record, record_table )
        if not rc:
            raise Exception("State transition sanity checks failed")

        rc = namedb_state_mutation_sanity_check( opcode, op_data_name )
        if not rc:
            raise Exception("State mutation sanity checks failed")

    except Exception, e:
        log.exception(e)
        log.error("FATAL: state transition sanity checks failed")
        os.abort()

    # 1. generate the new record that will be used for consensus.
    # It will be the new data overlayed on the current record, with all quirks applied.
    new_record = {}
    new_record.update(cur_record)
    new_record.update(op_data_name)
    new_record['opcode'] = opcode

    canonicalized_record = op_canonicalize_quirks(opcode, new_record, cur_record)
    canonicalized_record['opcode'] = opcode
    
    rc = namedb_history_save(cur, opcode, history_id, None, new_record.get('value_hash', None), block_id, vtxindex, txid, canonicalized_record)
    if not rc:
        log.error("FATAL: failed to save history for '%s' at (%s, %s)" % (history_id, block_id, vtxindex))
        os.abort()

    rc = False
    merged_new_record = None
    
    # 2. Store the actual op_data, to be returned on name lookups
    # Don't store extra fields that don't belong in the db (i.e. that we don't have colunms for), but preserve them across the write.
    stored_op_data = {}
    stored_op_data.update(op_data_name)

    # separate out the extras
    _, op_data_extra = namedb_find_missing_and_extra(cur, stored_op_data, record_table)
    if len(op_data_extra) > 0:
        log.debug("Remove extra fields: {}".format(','.join(op_data_extra)))
        for extra in op_data_extra:
            del stored_op_data[extra]
    
    if opcode in OPCODE_NAME_STATE_TRANSITIONS:
        # name state transition 
        rc = namedb_name_update( cur, opcode, stored_op_data, constraints_ignored=constraints_ignored )
        if not rc:
            log.error("FATAL: opcode is not a state-transition operation on names")
            os.abort()

        merged_new_record = namedb_get_name(cur, history_id, block_id, include_history=False, include_expired=True)

    elif opcode in OPCODE_NAMESPACE_STATE_TRANSITIONS:
        # namespace state transition 
        rc = namedb_namespace_update( cur, opcode, stored_op_data, constraints_ignored=constraints_ignored )
        if not rc:
            log.error("FATAL: opcode is not a state-transition operation on namespaces")
            os.abort()

        merged_new_record = namedb_get_namespace(cur, history_id, block_id, include_history=False, include_expired=True)

    # 3. success! make sure the merged_new_record is consistent with canonicalized_record
    for f in merged_new_record:
        if f not in canonicalized_record:
            raise Exception("canonicalized record is missing {}".format(f))

    return canonicalized_record
    

def namedb_state_create_sanity_check( opcode, op_data, history_id, preorder_record, record_table ):
    """
    Sanity checks on a preorder and a state-creation operation:
    * the opcode must match the op_data
    * the history_id and operation must match the preorder
    * everything must match the record table.

    Return True on success
    Raise an exception on error.

    DO NOT CALL THIS METHOD DIRECTLY.
    """

    namedb_op_sanity_check( opcode, op_data, preorder_record )
    preorder_opcode = op_get_opcode_name(preorder_record['op'])

    if opcode in OPCODE_NAME_STATE_CREATIONS:
        # name state transition 
        assert record_table == "name_records", "BUG: name state transition opcode (%s) on table %s" % (opcode, record_table)
        assert preorder_opcode in OPCODE_NAME_STATE_PREORDER, "BUG: preorder record opcode '%s' is not a name preorder" % (preorder_opcode)

        assert 'name' in op_data, 'BUG: no name in op_data'
        assert 'block_number' in op_data, 'BUG: no block_number in op_data'

    elif opcode in OPCODE_NAMESPACE_STATE_CREATIONS:
        # namespace state transition 
        assert record_table == "namespaces", "BUG: namespace state transition opcode (%s) on table %s" % (opcode, record_table)
        assert preorder_opcode in OPCODE_NAMESPACE_STATE_PREORDER, "BUG: preorder record opcode '%s' is not a namespace preorder" % (preorder_opcode)
        
        assert 'namespace_id' in op_data, 'BUG: no namespace_id in op_data'
        assert 'block_number' in op_data, 'BUG: no block_number in op_data'

    return True


def namedb_state_create( cur, opcode, new_record, block_id, vtxindex, txid, history_id, preorder_record, record_table, constraints_ignored=[] ):
    """
    Given an operation and a new record (opcode, new_record), a point in time (block_id, vtxindex, txid), and a preorder
    record for a known record (history_id, preorder_record), create the initial name or namespace using
    the preorder and operation's data.  Record the preorder as history.

    This operation will allow the caller to update an existing name or namespace if it is being re-registered.
    It is up to the caller to verify that the name or namespace does not exist at the time of this call.

    Returns the data to snapshot on success (with all compatibility quirks preserved)
    Raise an exception on failure.

    DO NOT CALL THIS METHOD DIRECTLY.
    """

    # sanity check: must be a state-creation operation 
    if opcode not in OPCODE_NAME_STATE_CREATIONS + OPCODE_NAMESPACE_STATE_CREATIONS or opcode in OPCODE_NAME_STATE_IMPORTS:
        log.error("FATAL: Opcode '%s' is not a state-creating operation" % opcode)
        os.abort()
    
    # did this name or namespace previously exist?
    exists = False
    prev_rec = None
    if opcode in OPCODE_NAMESPACE_STATE_CREATIONS:
        prev_rec = namedb_get_namespace(cur, history_id, block_id, include_expired=True, include_history=False)
        if prev_rec is not None:
            exists = True

    elif opcode in OPCODE_NAME_STATE_CREATIONS or opcode in OPCODE_NAME_STATE_IMPORTS:
        prev_rec = namedb_get_name(cur, history_id, block_id, include_expired=True, include_history=False)
        if prev_rec is not None:
            exists = True
    
    # the record we insert into the history table
    preorder_record_history = {}
    preorder_record_history.update(preorder_record)

    try:
        assert 'op' in preorder_record_history.keys(), 'BUG: no preorder op'
        assert 'preorder_hash' in preorder_record_history.keys(), "BUG: no preorder hash"
        assert 'block_number' in preorder_record_history.keys(), "BUG: preorder has no block number"
        assert 'vtxindex' in preorder_record_history.keys(), "BUG: preorder has no vtxindex"
        assert 'txid' in preorder_record_history.keys(), "BUG: preorder has no txid"
        assert 'burn_address' in preorder_record_history.keys(), 'BUG: preorder has no burn address'
        assert 'op_fee' in preorder_record_history.keys(), 'BUG: preorder has no op fee'

        if prev_rec is not None:
            # block_number cannot change
            assert prev_rec['block_number'] == new_record['block_number'], 'BUG: trying to change block number from {} to {} for "{}"'.format(prev_rec['block_number'], new_record['block_number'], history_id)

    except Exception, e:
        log.exception(e)
        log.error("FATAL: no preorder hash")
        os.abort()
        
    try:
        if not exists:
            # sanity check to make sure we got valid state-creation data
            rc = namedb_state_create_sanity_check( opcode, new_record, history_id, preorder_record, record_table )
            if not rc:
                raise Exception("state-creation sanity check on '%s' failed" % opcode )

        rc = namedb_state_mutation_sanity_check( opcode, new_record )
        if not rc:
            raise Exception("State mutation sanity checks failed")

        assert 'opcode' not in new_record, 'BUG: opcode not allowed in op_data'

    except Exception, e:
        log.exception(e)
        log.error("FATAL: state-creation sanity check failed")
        os.abort()

    # save the preorder as history.
    rc = namedb_history_save(cur, preorder_record['opcode'], history_id, None, None, preorder_record['block_number'], preorder_record['vtxindex'], preorder_record['txid'], preorder_record_history)
    if not rc:
        log.error("FATAL: failed to save preorder for {} at ({}, {})".format(history_id, preorder_record['block_number'], preorder_record['vtxindex']))
        os.abort()

    # save new record
    history_data = {}
    history_data.update(new_record)
    history_data['opcode'] = opcode
    
    canonicalized_record = op_canonicalize_quirks(opcode, history_data, prev_rec)
    canonicalized_record['opcode'] = opcode

    rc = namedb_history_save(cur, opcode, history_id, history_data['address'], history_data.get('value_hash', None), block_id, vtxindex, txid, canonicalized_record)
    if not rc:
        log.error("FATAL: failed to save history for '%s' at (%s, %s)" % (history_id, block_id, vtxindex))
        os.abort()

    rc = False
    if opcode in OPCODE_NAME_STATE_CREATIONS:
        # name state transition 
        if exists:
            # update existing name entry (i.e. re-registering it)
            rc = namedb_name_update(cur, opcode, new_record, constraints_ignored=constraints_ignored)
        else:
            # insert new entry
            rc = namedb_name_insert(cur, new_record)

    elif opcode in OPCODE_NAMESPACE_STATE_CREATIONS:
        # namespace state transition 
        if exists:
            # update existing namespace entry (i.e. re-revealing it) 
            rc = namedb_namespace_update(cur, opcode, new_record, constraints_ignored=constraints_ignored)
        else:
            # insert new entry
            rc = namedb_namespace_insert(cur, new_record)
    
    if not rc:
        log.error("FATAL: opcode is not a state-creation operation")
        os.abort()

    # clear the associated preorder 
    rc = namedb_preorder_remove( cur, preorder_record['preorder_hash'] )
    if not rc:
        log.error("FATAL: failed to remove preorder")
        os.abort()

    # success!  canonicalize and preserve quirks
    return canonicalized_record


def namedb_name_import_sanity_check( cur, opcode, op_data, history_id, block_id, vtxindex, prior_import, record_table):
    """
    Sanity checks on a name-import:
    * the opcode must match the op_data
    * everything must match the record table.
    * if prior_import is None, then the name shouldn't exist
    * if prior_import is not None, then it must exist

    Return True on success
    Raise an exception on error.

    DO NOT CALL THIS METHOD DIRECTLY.
    """

    assert opcode in OPCODE_NAME_STATE_IMPORTS, "BUG: opcode '%s' does not import a name" % (opcode)
    assert record_table == "name_records", "BUG: wrong table %s" % record_table
    assert namedb_is_history_snapshot( op_data ), "BUG: import is incomplete"
    
    namedb_op_sanity_check( opcode, op_data, op_data )

    # must be the only such existant name, if prior_import is None
    name_rec = namedb_get_name( cur, history_id, block_id )
    if prior_import is None:
        assert name_rec is None, "BUG: trying to import '%s' for the first time, again" % history_id
    else:
        assert name_rec is not None, "BUG: trying to overwrite non-existent import '%s'" % history_id
        assert prior_import['name'] == history_id, "BUG: trying to overwrite import for different name '%s'" % history_id
        
        # must actually be prior
        assert prior_import['block_number'] < block_id or (prior_import['block_number'] == block_id and prior_import['vtxindex'] < vtxindex), \
                "BUG: prior_import comes after op_data"

    return True


def namedb_get_last_name_import(cur, name, block_id, vtxindex):
    """
    Find the last name import for this name
    """
    query = 'SELECT history_data FROM history WHERE history_id = ? AND (block_id < ? OR (block_id = ? AND vtxindex < ?)) ' + \
            'ORDER BY block_id DESC,vtxindex DESC LIMIT 1;'

    args = (name, block_id, block_id, vtxindex)

    history_rows = namedb_query_execute(cur, query, args)

    for row in history_rows:
        history_data = json.loads(row['history_data'])
        return history_data

    return None


def namedb_state_create_as_import( db, opcode, new_record, block_id, vtxindex, txid, history_id, record_table, constraints_ignored=[] ):
    """
    Given an operation and a new record (opcode, new_record), and point in time (block_id, vtxindex, txid)
    create the initial name as an import.  Does not work on namespaces.

    Returns the data to snapshot on success (with all compatibility quirks preserved)
    Raise an exception on failure.

    DO NOT CALL THIS METHOD DIRECTLY.
    """

    # sanity check: must be a name, and must be an import
    if opcode not in OPCODE_NAME_STATE_IMPORTS:
        log.error("FATAL: Opcode '%s' is not a state-importing operation" % opcode)
        os.abort()

    cur = db.cursor()

    # does a previous version of this record exist?
    prior_import = namedb_get_last_name_import(cur, history_id, block_id, vtxindex)

    try:

        # sanity check to make sure we got valid state-import data
        rc = namedb_name_import_sanity_check( cur, opcode, new_record, history_id, block_id, vtxindex, prior_import, record_table )
        if not rc:
            raise Exception("state-import sanity check on '%s' failed" % opcode )

        rc = namedb_state_mutation_sanity_check( opcode, new_record )
        if not rc:
            raise Exception("State mutation sanity checks failed")
        
        assert 'opcode' not in new_record, 'BUG: opcode in new_record'

    except Exception, e:
        log.exception(e)
        log.error("FATAL: state-import sanity check failed")
        os.abort()

    cur = db.cursor()
    creator_address = None
    if prior_import is None:
        # creating for the first time
        creator_address = new_record['address']

    history_data = {}
    history_data.update(new_record)
    history_data['opcode'] = opcode

    canonicalized_record = op_canonicalize_quirks(opcode, new_record, prior_import)
    canonicalized_record['opcode'] = opcode

    rc = namedb_history_save(cur, opcode, history_id, creator_address, history_data.get('value_hash', None), block_id, vtxindex, txid, canonicalized_record)
    if not rc:
        log.error("FATAL: failed to save history snapshot for '%s' at (%s, %s)" % (history_id, block_id, vtxindex))
        os.abort()

    if prior_import is None:
        # creating for the first time
        cur = db.cursor()
        rc = namedb_name_insert(cur, new_record)

    else:
        # updating an existing import 
        rc = namedb_name_update(cur, opcode, new_record, constraints_ignored=constraints_ignored)

    if not rc:
        log.error("FATAL: failed to execute import operation")
        os.abort()

    # success!  canonicalize and preserve quirks
    return canonicalized_record


def namedb_is_history_snapshot( history_snapshot ):
    """
    Given a dict, verify that it is a history snapshot.
    It must have all consensus fields.
    Return True if so.
    Raise an exception of it doesn't.
    """
    
    # sanity check:  each mutate field in the operation must be defined in op_data, even if it's null.
    missing = []

    assert 'op' in history_snapshot.keys(), "BUG: no op given"

    opcode = op_get_opcode_name( history_snapshot['op'] )
    assert opcode is not None, "BUG: unrecognized op '%s'" % history_snapshot['op']

    consensus_fields = op_get_consensus_fields( opcode )
    for field in consensus_fields:
        if field not in history_snapshot.keys():
            missing.append( field )

    assert len(missing) == 0, ("BUG: operation '%s' is missing the following fields: %s" % (opcode, ",".join(missing)))
    return True


def namedb_history_save( cur, opcode, history_id, creator_address, value_hash, block_id, vtxindex, txid, accepted_rec, history_snapshot=False ):
    """
    Insert data into the state engine's history.
    It must be for a never-before-seen (txid,block_id,vtxindex) set.
    @history_id is either the name or namespace ID

    Return True on success
    Raise an Exception on error
    """

    assert 'op' in accepted_rec, "Malformed record at ({},{}): missing op".format(block_id, accepted_rec['vtxindex'])
    
    op = accepted_rec['op']
   
    record_data = op_canonicalize(opcode, accepted_rec)
    record_txt = json.dumps(record_data, sort_keys=True)

    history_insert = {
        "txid": txid,
        "history_id": history_id,
        "creator_address": creator_address,
        "block_id": block_id,
        "vtxindex": vtxindex,
        "op": op,
        "opcode": opcode,
        "history_data": record_txt,
        'value_hash': value_hash
    }

    try:
        query, values = namedb_insert_prepare( cur, history_insert, "history" )
    except Exception, e:
        log.exception(e)
        log.error("FATAL: failed to append history record for '%s' at (%s, %s)" % (history_id, block_id, vtxindex))
        os.abort()

    namedb_query_execute( cur, query, values )
    return True


def namedb_get_history_rows( cur, history_id, offset=None, count=None, reverse=False ):
    """
    Get the history for a name or namespace from the history table.
    Use offset/count if given.
    """
    ret = []
    if not reverse:
        select_query = "SELECT * FROM history WHERE history_id = ? ORDER BY block_id ASC, vtxindex ASC"
    else:
        select_query = "SELECT * FROM history WHERE history_id = ? ORDER BY block_id DESC, vtxindex DESC"

    args = (history_id,)

    if count is not None:
        select_query += " LIMIT ?"
        args += (count,)

        if offset is not None:
            select_query += " OFFSET ?"
            args += (offset,)

    select_query += ";"

    history_rows = namedb_query_execute( cur, select_query, args)
    for r in history_rows:
        rd = dict(r)
        ret.append(rd)

    return ret


def namedb_get_num_history_rows( cur, history_id ):
    """
    Get the history for a name or namespace from the history table.
    Use offset/count if given.
    """
    ret = []
    select_query = "SELECT COUNT(*) FROM history WHERE history_id = ? ORDER BY block_id ASC, vtxindex ASC;"
    args = (history_id,)

    count = namedb_select_count_rows( cur, select_query, args )
    return count


def namedb_get_history( cur, history_id, offset=None, count=None, reverse=False ):
    """
    Get all of the history for a name or namespace.
    Returns a dict keyed by block heights, paired to lists of changes (see namedb_history_extract)
    """
    # get history in increasing order by block_id and then vtxindex
    history_rows = namedb_get_history_rows( cur, history_id, offset=offset, count=count, reverse=reverse )
    return namedb_history_extract( history_rows )


def namedb_history_extract( history_rows ):
    """
    Given the rows of history for a name, collapse
    them into a history dictionary.
    Return a dict of:
    {
        block_id: [
            { ... historical copy ...
             txid:
             vtxindex:
             op:
             opcode: 
            }, ...
        ],
        ...
    }
    """

    history = {}
    for history_row in history_rows:

        block_id = history_row['block_id']
        data_json = history_row['history_data']
        hist = json.loads( data_json )
        
        hist['opcode'] = op_get_opcode_name( hist['op'] )
        hist = op_decanonicalize(hist['opcode'], hist)

        if history.has_key( block_id ):
            history[ block_id ].append( hist )
        else:
            history[ block_id ] = [ hist ]

    return history


def namedb_flatten_history( hist ):
    """
    Given a name's history, flatten it into a list of deltas.
    They will be in *increasing* order.
    """
    ret = []
    block_ids = sorted(hist.keys())
    for block_id in block_ids:
        vtxinfos = hist[block_id]
        for vtxinfo in vtxinfos:
            info = copy.deepcopy(vtxinfo)
            ret.append(info)

    return ret


def namedb_get_namespace( cur, namespace_id, current_block, include_expired=False, include_history=True, only_revealed=True):
    """
    Get a namespace (revealed or ready) and optionally its history.
    Only return an expired namespace if asked.
    If current_block is None, any namespace is returned (expired or not)
    If current_block is not None and only_revealed is False, then a namespace can be returned before it was revealed.
    -- if include_expired is False, then a namespace can be returned only if current_block is less than the expire block
    -- otherwise, any namespace can be returned
    """

    include_expired_query = ""
    include_expired_args = ()

    min_age_query = ""
    min_age_args = ()

    if only_revealed:
        # requier lower bound on age
        min_age_query = " AND namespaces.reveal_block <= ?"
        min_age_args = (current_block,)

    if not include_expired:
        assert current_block is not None
        # require upper bound on age
        include_expired_query = " AND ? < namespaces.reveal_block + ?"
        include_expired_args = (current_block, NAMESPACE_REVEAL_EXPIRE)

    if current_block is None:
        # no bounds on age
        min_age_query = ""
        min_age_args = ()

    select_query = "SELECT * FROM namespaces WHERE namespace_id = ? AND " + \
                   "((op = ?) OR (op = ? %s %s))" % (min_age_query, include_expired_query)

    args = (namespace_id, NAMESPACE_READY, NAMESPACE_REVEAL) + min_age_args + include_expired_args

    log.debug(namedb_format_query(select_query, args))

    namespace_rows = namedb_query_execute( cur, select_query, args )

    namespace_row = namespace_rows.fetchone()
    if namespace_row is None:
        # no such namespace 
        return None 

    namespace = {}
    namespace.update( namespace_row )

    if include_history:
        hist = namedb_get_history( cur, namespace_id )
        namespace['history'] = hist

    namespace = op_decanonicalize(op_get_opcode_name(namespace['op']), namespace)
    return namespace


def namedb_get_namespace_by_preorder_hash( cur, preorder_hash, include_history=True ):
    """
    Get a namespace by its preorder hash (regardless of whether or not it was expired.)
    """

    select_query = "SELECT * FROM namespaces WHERE preorder_hash = ?;"
    namespace_rows = namedb_query_execute( cur, select_query, (preorder_hash,))

    namespace_row = namespace_rows.fetchone()
    if namespace_row is None:
        # no such namespace 
        return None 

    namespace = {}
    namespace.update( namespace_row )

    if include_history:
        hist = namedb_get_history( cur, namespace['namespace_id'] )
        namespace['history'] = hist

    namespace = op_decanonicalize(op_get_opcode_name(namespace['op']), namespace)
    return namespace


def namedb_get_name_by_preorder_hash( cur, preorder_hash, include_history=True ):
    """
    Get a name by its preorder hash (regardless of whether or not it was expired or revoked.)
    """

    select_query = "SELECT * FROM name_records WHERE preorder_hash = ?;"
    name_rows = namedb_query_execute( cur, select_query, (preorder_hash,))

    name_row = name_rows.fetchone()
    if name_row is None:
        # no such preorder
        return None 

    namerec = {}
    namerec.update( name_row )

    if include_history:
        hist = namedb_get_history( cur, namerec['name'] )
        namerec['history'] = hist

    return namerec


def namedb_select_where_unexpired_names(current_block, only_registered=True):
    """
    Generate part of a WHERE clause that selects from name records joined with namespaces
    (or projections of them) that are not expired.

    Also limit to names that are registered at this block, if only_registered=True.
    If only_registered is False, then as long as current_block is before the expire block, then the name will be returned (but the name may not have existed at that block)
    """

    ns_lifetime_multiplier = get_epoch_namespace_lifetime_multiplier(current_block, '*')
    ns_grace_period = get_epoch_namespace_lifetime_grace_period(current_block, '*')

    unexpired_query_fragment =  "(" + \
                                    "(" + \
                                        "namespaces.op = ? AND " + \
                                        "(" + \
                                            "(namespaces.ready_block + ((namespaces.lifetime * {}) + {}) > ?) OR ".format(ns_lifetime_multiplier, ns_grace_period) + \
                                            "(name_records.last_renewed + ((namespaces.lifetime * {}) + {}) >= ?)".format(ns_lifetime_multiplier, ns_grace_period) + \
                                        ")" + \
                                    ") OR " + \
                                    "(" + \
                                        "namespaces.op = ? AND namespaces.reveal_block <= ? AND ? < namespaces.reveal_block + ?" + \
                                    ")" + \
                                ")"

    unexpired_query_args = (NAMESPACE_READY, 
                                current_block,
                                current_block,
                            NAMESPACE_REVEAL, current_block, current_block, NAMESPACE_REVEAL_EXPIRE)
    
    if only_registered:
        # also limit to only names registered before this block
        unexpired_query_fragment = '(name_records.first_registered <= ? AND {})'.format(unexpired_query_fragment)
        unexpired_query_args = (current_block,) + unexpired_query_args

    return (unexpired_query_fragment, unexpired_query_args)


def namedb_get_name(cur, name, current_block, include_expired=False, include_history=True, only_registered=True):
    """
    Get a name and all of its history.  Note: will return a revoked name
    Return the name + history on success
    Return None if the name doesn't exist, or is expired (NOTE: will return a revoked name)
    """

    if not include_expired:

        unexpired_fragment, unexpired_args = namedb_select_where_unexpired_names(current_block, only_registered=only_registered)
        select_query = "SELECT name_records.* FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id " + \
                       "WHERE name = ? AND " + unexpired_fragment + ";"
        args = (name, ) + unexpired_args

    else:
        select_query = "SELECT * FROM name_records WHERE name = ?;"
        args = (name,)

    # log.debug(namedb_format_query(select_query, args))

    name_rows = namedb_query_execute( cur, select_query, args )
    name_row = name_rows.fetchone()
    if name_row is None:
        # no such name
        return None 

    name_rec = {}
    name_rec.update( name_row )
    
    if include_history:
        name_history = namedb_get_history( cur, name )
        name_rec['history'] = name_history

    return name_rec


def namedb_get_name_DID_info(cur, name, block_height):
    """
    Given a name and a DB cursor, find out its DID info at the given block.
    Returns {'name_type': ..., 'address': ..., 'index': ...} on success
    Return None if there is no such name
    """
    # get the latest creator addresses for this name, as well as where this name was created in the blockchain
    sql = "SELECT name_records.name,history.creator_address,history.block_id,history.vtxindex FROM name_records JOIN history ON name_records.name = history.history_id " + \
          "WHERE name = ? AND creator_address IS NOT NULL AND history.block_id <= ? ORDER BY history.block_id DESC, history.vtxindex DESC LIMIT 1;"
    args = (name,block_height)

    # log.debug(namedb_format_query(sql, args))
    rows = namedb_query_execute(cur, sql, args)
    row = rows.fetchone()
    if row is None:
        return None
    
    creator_address = row['creator_address']
    latest_block_height = row['block_id']
    latest_vtxindex = row['vtxindex']

    # how many names has this address created up to this name?
    query = "SELECT COUNT(*) FROM name_records JOIN history ON name_records.name = history.history_id " + \
            "WHERE history.creator_address = ? AND (history.block_id < ? OR (history.block_id = ? AND history.vtxindex <= ?));"

    args = (creator_address,latest_block_height,latest_block_height,latest_vtxindex)

    # log.debug(namedb_format_query(query, args))
    count_rows = namedb_query_execute(cur, query, args)
    count_row = count_rows.fetchone()
    if count_row is None:
        return None

    count = count_row['COUNT(*)'] - 1

    return {'name_type': 'name', 'address': str(creator_address), 'index': count}


def namedb_get_record_states_at(cur, history_id, block_number):
    """
    Get the state(s) that the given history record was in at a given block height.
    Normally, this is one state (i.e. if a name was registered at block 8, then it is in a NAME_REGISTRATION state in block 10)

    However, if the record changed at this block, then this method returns all states the record passed through.

    Returns an array of record states
    """
    query = 'SELECT block_id,history_data FROM history WHERE history_id = ? AND block_id == ? ORDER BY block_id DESC,vtxindex DESC'
    args = (history_id, block_number)
    history_rows = namedb_query_execute(cur, query, args)
    ret = []

    for row in history_rows:
        history_data = simplejson.loads(row['history_data'])
        ret.append(history_data)

    if len(ret) > 0:
        # record changed in this block
        return ret
    
    # if the record did not change in this block, then find the last version of the record
    query = 'SELECT block_id,history_data FROM history WHERE history_id = ? AND block_id < ? ORDER BY block_id DESC,vtxindex DESC LIMIT 1'
    args = (history_id, block_number)
    history_rows = namedb_query_execute(cur, query, args)
    
    for row in history_rows:
        history_data = simplejson.loads(row['history_data'])
        ret.append(history_data)

    return ret


def namedb_get_name_at(cur, name, block_number, include_expired=False):
    """
    Get the sequence of states that a name record was in at a particular block height.
    There can be more than one if the name changed during the block.

    Returns only unexpired names by default.  Can return expired names with include_expired=True
    Returns None if this name does not exist at this block height.
    """
    if not include_expired:
        # don't return anything if this name is expired.
        # however, we don't care if the name hasn't been created as of this block_number either, since we might return its preorder (hence only_registered=False)
        name_rec = namedb_get_name(cur, name, block_number, include_expired=False, include_history=False, only_registered=False)
        if name_rec is None:
            # expired at this block.
            return None

    history_rows = namedb_get_record_states_at(cur, name, block_number)
    if len(history_rows) == 0:
        # doesn't exist
        return None
    else:
        return history_rows


def namedb_get_namespace_at(cur, namespace_id, block_number, include_expired=False):
    """
    Get the sequence of states that a namespace record was in at a particular block height.
    There can be more than one if the namespace changed durnig the block.
    
    Returns only unexpired namespaces by default.  Can return expired namespaces with include_expired=True
    """
    if not include_expired:
        # don't return anything if the namespace was expired at this block.
        # (but do return something here even if the namespace was created after this block, so we can potentially pick up its preorder (hence only_revealed=False))
        namespace_rec = namedb_get_namespace(cur, namespace_id, block_number, include_expired=False, include_history=False, only_revealed=False)
        if namespace_rec is None:
            # expired at this block
            return None

    history_rows = namedb_get_record_states_at(cur, namespace_id, block_number)
    if len(history_rows) == 0:
        # doesn't exist yet 
        return None
    else:
        return history_rows


def namedb_get_preorder(cur, preorder_hash, current_block_number, include_expired=False, expiry_time=None):
    """
    Get a preorder record by hash.
    If include_expired is set, then so must expiry_time
    Return None if not found.
    """

    select_query = None 
    args = None 

    if include_expired:
        select_query = "SELECT * FROM preorders WHERE preorder_hash = ?;"
        args = (preorder_hash,)

    else:
        assert expiry_time is not None, "expiry_time is required with include_expired"
        select_query = "SELECT * FROM preorders WHERE preorder_hash = ? AND block_number < ?;"
        args = (preorder_hash, expiry_time + current_block_number)

    preorder_rows = namedb_query_execute( cur, select_query, (preorder_hash,))
    preorder_row = preorder_rows.fetchone()
    if preorder_row is None:
        # no such preorder 
        return None

    preorder_rec = {}
    preorder_rec.update( preorder_row )
    
    return preorder_rec


def namedb_get_names_owned_by_address( cur, address, current_block ):
    """
    Get the list of non-expired, non-revoked names owned by an address.
    Only works if there is a *singular* address for the name.
    """

    unexpired_fragment, unexpired_args = namedb_select_where_unexpired_names( current_block )

    select_query = "SELECT name FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id " + \
                   "WHERE name_records.address = ? AND name_records.revoked = 0 AND " + unexpired_fragment + ";"
    args = (address,) + unexpired_args

    name_rows = namedb_query_execute( cur, select_query, args )

    names = []
    for name_row in name_rows:
        names.append( name_row['name'] )

    if len(names) == 0:
        return None 
    else:
        return names


def namedb_get_num_historic_names_by_address( cur, address ):
    """
    Get the number of names owned by an address throughout history
    """

    select_query = "SELECT COUNT(*) FROM name_records JOIN history ON name_records.name = history.history_id " + \
                   "WHERE history.creator_address = ?;"

    args = (address,)

    count = namedb_select_count_rows( cur, select_query, args )
    return count
    

def namedb_get_historic_names_by_address( cur, address, offset=None, count=None ):
    """
    Get the list of all names ever owned by this address (except the current one), ordered by creation date.
    Return a list of {'name': ..., 'block_id': ..., 'vtxindex': ...}}
    """

    query = "SELECT name_records.name,history.block_id,history.vtxindex FROM name_records JOIN history ON name_records.name = history.history_id " + \
            "WHERE history.creator_address = ? ORDER BY history.block_id, history.vtxindex "

    args = (address,)

    offset_count_query, offset_count_args = namedb_offset_count_predicate( offset=offset, count=count )
    query += offset_count_query + ";"
    args += offset_count_args

    name_rows = namedb_query_execute( cur, query, args )

    names = []
    for name_row in name_rows:
        info = {
            'name': name_row['name'], 
            'block_id': name_row['block_id'], 
            'vtxindex': name_row['vtxindex']
        }

        names.append( info )

    if len(names) == 0:
        return None 
    else:
        return names


def namedb_offset_count_predicate( offset=None, count=None ):
    """
    Make an offset/count predicate
    even if offset=None or count=None.

    Return (query, args)
    """
    offset_count_query = ""
    offset_count_args = ()

    if count is not None:
        offset_count_query += "LIMIT ? "
        offset_count_args += (count,)

    if count is not None and offset is not None:
        offset_count_query += "OFFSET ? "
        offset_count_args += (offset,)

    return (offset_count_query, offset_count_args)


def namedb_select_count_rows( cur, query, args, count_column='COUNT(*)' ):
    """
    Execute a SELECT COUNT(*) ... query
    and return the number of rows.
    """
    count_rows = namedb_query_execute( cur, query, args )
    count = 0
    for r in count_rows:
        count = r[count_column]
        break

    return count


def namedb_get_all_blockstack_ops_at(db, block_id, offset=None, count=None):
    """
    Get the states that each name and namespace record
    passed through in the given block.  Note that this only concerns
    operations written on-chain, for use in SNV and database verification

    Return the list of prior record states, ordered by vtxindex.
    """
    assert (count is None and offset is None) or (count is not None and offset is not None), 'Invalid arguments: expect both offset/count or neither offset/count'

    ret = []
    cur = db.cursor()

    # how many preorders at this block?
    offset_count_query, offset_count_args = namedb_offset_count_predicate(offset=offset, count=count)

    # be sure to order by vtxindex for database verification and SNV
    preorder_count_rows_query = "SELECT COUNT(*) FROM preorders WHERE block_number = ? ORDER BY vtxindex " + " " + offset_count_query + ";"
    preorder_count_rows_args = (block_id,) + offset_count_args

    # log.debug(namedb_format_query(preorder_count_rows_query, preorder_count_rows_args))

    num_preorders = namedb_select_count_rows(cur, preorder_count_rows_query, preorder_count_rows_args)

    # get preorders at this block
    offset_count_query, offset_count_args = namedb_offset_count_predicate(offset=offset, count=count)

    preorder_rows_query = "SELECT * FROM preorders WHERE block_number = ? " + " " + offset_count_query + ";"
    preorder_rows_args = (block_id,) + offset_count_args

    # log.debug(namedb_format_query(preorder_rows_query, preorder_rows_args))

    preorder_rows = namedb_query_execute(cur, preorder_rows_query, preorder_rows_args)

    cnt = 0
    for preorder in preorder_rows:
        preorder_rec = {}
        preorder_rec.update( preorder )
        
        ret.append( preorder_rec )
        cnt += 1

    log.debug("{} preorders created at {}".format(cnt, block_id))

    # don't return too many rows, and slide down the offset window
    if count is not None and offset is not None:
        offset = max(0, offset - num_preorders)
        count -= num_preorders
        if count <= 0:
            # done!
            return ret

    # get all other operations at this block (name ops, namespace ops, token ops)
    offset_count_query, offset_count_args = namedb_offset_count_predicate(offset=offset, count=count)
    query = "SELECT history_data FROM history WHERE block_id = ? ORDER BY vtxindex " + offset_count_query + ";"
    args = (block_id,) + offset_count_args

    # log.debug(namedb_format_query(query, args))

    rows_result = namedb_query_execute(cur, query, args)

    # extract rows
    cnt = 0
    for r in rows_result:
        history_data_str = r['history_data']

        try:
            history_data = json.loads(history_data_str)
        except Exception as e:
            log.exception(e)
            log.error("FATAL: corrupt JSON string '{}'".format(history_data_str))
            os.abort()

        ret.append(history_data)
        cnt += 1

    log.debug("{} non-preorder operations at {}".format(cnt, block_id))
    return ret


def namedb_get_num_blockstack_ops_at( db, block_id ):
    """
    Get the number of name/namespace/token operations that occurred at a particular block.
    """
    cur = db.cursor()

    # preorders at this block
    preorder_count_rows_query = "SELECT COUNT(*) FROM preorders WHERE block_number = ?;"
    preorder_count_rows_args = (block_id,)
    
    num_preorders = namedb_select_count_rows(cur, preorder_count_rows_query, preorder_count_rows_args)

    # committed operations at this block
    query = "SELECT COUNT(*) FROM history WHERE block_id = ?;"
    args = (block_id,)

    rows_result = namedb_query_execute(cur, query, args)

    count = 0
    for r in rows_result:
        count = r['COUNT(*)']
        break

    log.debug("{} preorders; {} history rows at {}".format(num_preorders, count, block_id))
    return count + num_preorders
    

def namedb_get_num_names( cur, current_block, include_expired=False ):
    """
    Get the number of names that exist at the current block
    """
    unexpired_query = ""
    unexpired_args = ()

    if not include_expired:
        # count all names, including expired ones
        unexpired_query, unexpired_args = namedb_select_where_unexpired_names( current_block )
        unexpired_query = 'WHERE {}'.format(unexpired_query)

    query = "SELECT COUNT(name_records.name) FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id " + unexpired_query + ";"
    args = unexpired_args

    num_rows = namedb_select_count_rows( cur, query, args, count_column='COUNT(name_records.name)' )
    return num_rows


def namedb_get_all_names( cur, current_block, offset=None, count=None, include_expired=False ):
    """
    Get a list of all names in the database, optionally
    paginated with offset and count.  Exclude expired names.  Include revoked names.
    """

    unexpired_query = ""
    unexpired_args = ()

    if not include_expired:
        # all names, including expired ones
        unexpired_query, unexpired_args = namedb_select_where_unexpired_names( current_block )
        unexpired_query = 'WHERE {}'.format(unexpired_query)

    query = "SELECT name FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id " + unexpired_query + " ORDER BY name "
    args = unexpired_args

    offset_count_query, offset_count_args = namedb_offset_count_predicate( offset=offset, count=count )
    query += offset_count_query + ";"
    args += offset_count_args

    name_rows = namedb_query_execute( cur, query, tuple(args) )
    ret = []
    for name_row in name_rows:
        rec = {}
        rec.update( name_row )
        ret.append( rec['name'] )

    return ret 


def namedb_get_num_names_in_namespace( cur, namespace_id, current_block ):
    """
    Get the number of names in a given namespace
    """
    unexpired_query, unexpired_args = namedb_select_where_unexpired_names( current_block )

    query = "SELECT COUNT(name_records.name) FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id WHERE name_records.namespace_id = ? AND " + unexpired_query + " ORDER BY name;"
    args = (namespace_id,) + unexpired_args

    num_rows = namedb_select_count_rows( cur, query, args, count_column='COUNT(name_records.name)' )
    return num_rows


def namedb_get_names_in_namespace( cur, namespace_id, current_block, offset=None, count=None ):
    """
    Get a list of all names in a namespace, optionally
    paginated with offset and count.  Exclude expired names
    """

    unexpired_query, unexpired_args = namedb_select_where_unexpired_names( current_block )

    query = "SELECT name FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id WHERE name_records.namespace_id = ? AND " + unexpired_query + " ORDER BY name "
    args = (namespace_id,) + unexpired_args

    offset_count_query, offset_count_args = namedb_offset_count_predicate( offset=offset, count=count )
    query += offset_count_query + ";"
    args += offset_count_args

    name_rows = namedb_query_execute( cur, query, tuple(args) )
    ret = []
    for name_row in name_rows:
        rec = {}
        rec.update( name_row )
        ret.append( rec['name'] )

    return ret


def namedb_get_all_namespace_ids( cur ):
    """
    Get a list of all READY namespace IDs.
    """

    query = "SELECT namespace_id FROM namespaces WHERE op = ?;"
    args = (NAMESPACE_READY,)

    namespace_rows = namedb_query_execute( cur, query, args )
    ret = []
    for namespace_row in namespace_rows:
        ret.append( namespace_row['namespace_id'] )

    return ret


def namedb_get_all_preordered_namespace_hashes( cur, current_block ):
    """
    Get a list of all preordered namespace hashes that haven't expired yet.
    Used for testing
    """
    query = "SELECT preorder_hash FROM preorders WHERE op = ? AND block_number >= ? AND block_number < ?;"
    args = (NAMESPACE_PREORDER, current_block, current_block + NAMESPACE_PREORDER_EXPIRE )

    namespace_rows = namedb_query_execute( cur, query, args )
    ret = []
    for namespace_row in namespace_rows:
        ret.append( namespace_row['preorder_hash'] )

    return ret


def namedb_get_all_revealed_namespace_ids( self, current_block ):
    """
    Get all non-expired revealed namespaces.
    """
    
    query = "SELECT namespace_id FROM namespaces WHERE op = ? AND reveal_block < ?;"
    args = (NAMESPACE_REVEAL, current_block + NAMESPACE_REVEAL_EXPIRE )

    namespace_rows = namedb_query_execute( cur, query, args )
    ret = []
    for namespace_row in namespace_rows:
        ret.append( namespace_row['namespace_id'] )

    return ret


def namedb_get_all_importing_namespace_hashes( self, current_block ):
    """
    Get the list of all non-expired preordered and revealed namespace hashes.
    """

    query = "SELECT preorder_hash FROM namespaces WHERE (op = ? AND reveal_block < ?) OR (op = ? AND block_number < ?);"
    args = (NAMESPACE_REVEAL, current_block + NAMESPACE_REVEAL_EXPIRE, NAMESPACE_PREORDER, current_block + NAMESPACE_PREORDER_EXPIRE )

    namespace_rows = namedb_query_execute( cur, query, args )
    ret = []
    for namespace_row in namespace_rows:
        ret.append( namespace_row['preorder_hash'] )

    return ret


def namedb_get_names_by_sender( cur, sender, current_block ):
    """
    Given a sender pubkey script, find all the non-expired non-revoked names owned by it.
    Return None if the sender owns no names.
    """

    unexpired_query, unexpired_args = namedb_select_where_unexpired_names( current_block )

    query = "SELECT name_records.name FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id " + \
            "WHERE name_records.sender = ? AND name_records.revoked = 0 AND " + unexpired_query + ";"

    args = (sender,) + unexpired_args

    name_rows = namedb_query_execute( cur, query, args )
    names = []

    for name_row in name_rows:
        names.append( name_row['name'] )

    return names
    

def namedb_get_name_preorder( db, preorder_hash, current_block ):
    """
    Get a (singular) name preorder record outstanding at the given block, given the preorder hash.
    NOTE: returns expired preorders.
    
    Return the preorder record on success.
    Return None if not found.
    """

    select_query = "SELECT * FROM preorders WHERE preorder_hash = ? AND op = ? AND block_number < ?;"
    args = (preorder_hash, NAME_PREORDER, current_block + NAME_PREORDER_EXPIRE)

    cur = db.cursor()
    preorder_rows = namedb_query_execute( cur, select_query, args )
    
    preorder_row = preorder_rows.fetchone()
    if preorder_row is None:
        # no such preorder 
        return None 

    preorder_rec = {}
    preorder_rec.update( preorder_row )

    unexpired_query, unexpired_args = namedb_select_where_unexpired_names( current_block )

    # make sure that the name doesn't already exist 
    select_query = "SELECT name_records.preorder_hash " + \
                   "FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id " + \
                   "WHERE name_records.preorder_hash = ? AND " + \
                   unexpired_query + ";"

    args = (preorder_hash,) + unexpired_args
    
    cur = db.cursor()
    nm_rows = namedb_query_execute( cur, select_query, args )

    nm_row = nm_rows.fetchone()
    if nm_row is not None:
        # name with this preorder exists 
        return None 

    return preorder_rec


def namedb_get_namespace_preorder( db, namespace_preorder_hash, current_block ):
    """
    Get a namespace preorder, given its hash.

    Return the preorder record on success.
    Return None if not found, or if it expired, or if the namespace was revealed or readied.
    """

    cur = db.cursor()
    select_query = "SELECT * FROM preorders WHERE preorder_hash = ? AND op = ? AND block_number < ?;"
    args = (namespace_preorder_hash, NAMESPACE_PREORDER, current_block + NAMESPACE_PREORDER_EXPIRE)
    preorder_rows = namedb_query_execute( cur, select_query, args )

    preorder_row = preorder_rows.fetchone()
    if preorder_row is None:
        # no such preorder 
        return None 

    preorder_rec = {}
    preorder_rec.update( preorder_row )

    # make sure that the namespace doesn't already exist 
    cur = db.cursor()
    select_query = "SELECT preorder_hash FROM namespaces WHERE preorder_hash = ? AND ((op = ?) OR (op = ? AND reveal_block < ?));"
    args = (namespace_preorder_hash, NAMESPACE_READY, NAMESPACE_REVEAL, current_block + NAMESPACE_REVEAL_EXPIRE)
    ns_rows = namedb_query_execute( cur, select_query, args )

    ns_row = ns_rows.fetchone()
    if ns_row is not None:
        # exists
        return None 

    return preorder_rec


def namedb_get_namespace_reveal( cur, namespace_id, current_block, include_history=True ):
    """
    Get a namespace reveal, and optionally its history, given its namespace ID.
    Only return a namespace record if:
    * it is not ready
    * it is not expired
    """

    select_query = "SELECT * FROM namespaces WHERE namespace_id = ? AND op = ? AND reveal_block <= ? AND ? < reveal_block + ?;"
    args = (namespace_id, NAMESPACE_REVEAL, current_block, current_block, NAMESPACE_REVEAL_EXPIRE)

    namespace_reveal_rows = namedb_query_execute( cur, select_query, args )

    namespace_reveal_row = namespace_reveal_rows.fetchone()
    if namespace_reveal_row is None:
        # no such reveal 
        return None 

    reveal_rec = {}
    reveal_rec.update( namespace_reveal_row )

    if include_history:
        hist = namedb_get_history( cur, namespace_id )
        reveal_rec['history'] = hist
    
    reveal_rec = op_decanonicalize('NAMESPACE_REVEAL', reveal_rec)
    return reveal_rec


def namedb_get_namespace_ready( cur, namespace_id, include_history=True ):
    """
    Get a ready namespace, and optionally its history.
    Only return a namespace if it is ready.
    """

    select_query = "SELECT * FROM namespaces WHERE namespace_id = ? AND op = ?;"
    namespace_rows = namedb_query_execute( cur, select_query, (namespace_id, NAMESPACE_READY))

    namespace_row = namespace_rows.fetchone()
    if namespace_row is None:
        # no such namespace 
        return None 

    namespace = {}
    namespace.update( namespace_row )

    if include_history:
        hist = namedb_get_history( cur, namespace_id )
        namespace['history'] = hist

    namespace = op_decanonicalize('NAMESPACE_READY', namespace)
    return namespace


def namedb_get_name_from_name_hash128( cur, name_hash128, block_number ):
    """
    Given the hexlified 128-bit hash of a name, get the name.
    """

    unexpired_query, unexpired_args = namedb_select_where_unexpired_names( block_number )

    select_query = "SELECT name FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id " + \
                   "WHERE name_hash128 = ? AND revoked = 0 AND " + unexpired_query + ";"

    args = (name_hash128,) + unexpired_args
    name_rows = namedb_query_execute( cur, select_query, args )

    name_row = name_rows.fetchone()
    if name_row is None:
        # no such namespace 
        return None 

    return name_row['name']


def namedb_get_names_with_value_hash( cur, value_hash, block_number ):
    """
    Get the names with the given value hash.  Only includes current, non-revoked names.
    Return None if there are no names.
    """

    unexpired_query, unexpired_args = namedb_select_where_unexpired_names( block_number )
    select_query = "SELECT name FROM name_records JOIN namespaces ON name_records.namespace_id = namespaces.namespace_id " + \
                   "WHERE value_hash = ? AND revoked = 0 AND " + unexpired_query + ";"

    args = (value_hash,) + unexpired_args
    name_rows = namedb_query_execute( cur, select_query, args )
    names = []

    for name_row in name_rows:
        names.append( name_row['name'] )

    if len(names) == 0:
        return None
    else:
        return names


def namedb_get_value_hash_txids(cur, value_hash):
    """
    Get the list of txs that sent this value hash, ordered by block and vtxindex
    """
    query = 'SELECT txid FROM history WHERE value_hash = ? ORDER BY block_id,vtxindex;'
    args = (value_hash,)

    rows = namedb_query_execute(cur, query, args)
    txids = []
    
    for r in rows:
        # present
        txid = str(r['txid'])
        txids.append(txid)

    return txids


def namedb_get_num_block_vtxs( cur, block_number ):
    """
    How many virtual transactions were processed for this block?
    """ 
    select_query = "SELECT vtxindex FROM history WHERE history_id = ?;"
    args = (block_number,)

    rows = namedb_query_execute( cur, select_query, args )
    count = 0
    for r in rows:
        count += 1

    return count


def namedb_is_name_zonefile_hash(cur, name, zonefile_hash):
    """
    Determine if a zone file hash was sent by a name.
    Return True if so, false if not
    """
    select_query = 'SELECT COUNT(value_hash) FROM history WHERE history_id = ? AND value_hash = ?'
    select_args = (name,zonefile_hash)

    rows = namedb_query_execute(cur, select_query, select_args)
    count = None

    for r in rows:
        count = r['COUNT(value_hash)']
        break

    return count > 0


if __name__ == "__main__":
    # basic unit tests
    import random 
    import pybitcoin

    path = "/tmp/namedb.sqlite"
    if not os.path.exists( path ):
        db = namedb_create( path )
    else:
        db = namedb_open( path )

    name = "test%s.test" % random.randint( 0, 2**32 )
    sender = "76a9147144b3fef9fe537e2445f1c0dfb4ce007c51461288ac"
    sender_pubkey = "046a6582a6566aa4059b7361536e7e4ac3df4d77bf6e843c4c8207eaa12e0ca19e15fc59c959b4a5d6d1de975ab059d9255a795dd57b9c78656a070ea5002efe87"
    sender_address = "1BKufFedDrueBBFBXtiATB2PSdsBGZxf3N"
    recipient = "76a914d3d4a11953ce8ba01b08548997830c11b1ad9a7288ac"
    recipient_pubkey = "04f52b0c1558202cb4403faacb6a74ad8a0d23538f448184b1c8ce80a0325aad9af0877061c2fd72cebec8524a99951d5834a8b8b96ddf4e2d582ee9dd61864dae"
    recipient_address = "1LK4JDfxaYZjJAinao3q5KdrLCtW3AFeQ6"
    current_block_number = 373610
    prior_block_number = 373601
    txid = "ce99f01aa17995c77e041beee93cf3bcf47ef68d18c16f79edd120a204d7c808"
    vtxindex = 1
    op = NAME_REGISTRATION
    opcode = "NAME_REGISTRATION"
    op_fee = 640000
    consensus_hash = "54a451b8a09a2acd951b06bda2b8e69f"

    namespace_address = "12HcV1f7XtQTgSPt7r1mpyr1ppfnX8fPa4"
    namespace_base = 4
    namespace_block_number = 373500
    namespace_buckets = [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0]
    namespace_coeff = 250
    namespace_lifetime = 520000
    namespace_id = "test"
    namespace_id_hash = "6134faee8737a865995aa5423b55f1a8ec69fe4b"
    namespace_no_vowel_discount = 10
    namespace_nonalpha_discount = 10
    namespace_ready_block = 373600
    namespace_recipient = "76a914b7e40511f53f69045cb14c6c5a714d6a4ffe3a3788ac"
    namespace_recipient_address = "1HmKpCXiK4ExFbdTG1Y38jcrtx9KPkgYKX"
    namespace_reveal_block = 373510
    namespace_sender = "76a914b7e40511f53f69045cb14c6c5a714d6a4ffe3a3788ac"
    namespace_sender_pubkey = "04d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f35eaa22c01a35bee5817f03d769a3a38a3bb50182c61449ad125555daf26396fb"
    namespace_txid = "71754175ee3168ade90b74c78af58312708a7103fd2d8d17346cad7a49b934da"
    namespace_version = 1

    namespace_record = {
        "address": namespace_address,
        "base": namespace_base,
        "block_number": namespace_reveal_block,
        "buckets": namespace_buckets,
        "coeff": namespace_coeff,
        "lifetime": namespace_lifetime,
        "namespace_id": namespace_id,
        "no_vowel_discount": namespace_no_vowel_discount,
        "nonalpha_discount": namespace_nonalpha_discount,
        "preorder_hash": namespace_id_hash,
        "ready_block": namespace_ready_block,
        # "opcode": "NAMESPACE_READY",
        "op": NAMESPACE_REVEAL,
        "op_fee": 6140,
        "recipient": namespace_recipient,
        "recipient_address": namespace_recipient_address,
        "reveal_block": namespace_reveal_block,
        "sender": namespace_sender,
        "sender_pubkey": namespace_sender_pubkey,
        "txid": namespace_txid,
        "vtxindex": 3,
        "version": namespace_version
    }
    
    preorder_record = {
        # NOTE: was preorder_name_hash
        "preorder_hash": hash_name( name, sender, recipient_address ),
        "consensus_hash": consensus_hash,
        "block_number": prior_block_number,
        "sender": sender,
        "sender_pubkey": sender_pubkey,
        "address": "1Nrmkp6rhebJnL2wURkUrwH93Evaq1s3Yd",
        "fee": 12345,
        "op": NAME_PREORDER,
        "txid": "69c21d76a98dd450305200346602d38c2ee2c401a81acd3dbe9ead850ab6bc7b",
        "vtxindex": 20,
        "op_fee": 6400001
    }

    name_record = {
        'name': name,
        "preorder_hash": hash_name( name, sender, recipient_address ),
        'value_hash': None,             # i.e. the hex hash of profile data in immutable storage.
        'sender': str(recipient),       # the recipient is the expected future sender
        'sender_pubkey': str(recipient_pubkey),
        'address': str(recipient_address),

        'block_number': prior_block_number,
        'preorder_block_number': preorder_record['block_number'],
        'first_registered': current_block_number,
        'last_renewed': current_block_number,
        'revoked': False,

        'op': op,
        'txid': txid,
        'vtxindex': vtxindex,
        'op_fee': op_fee,

        # (not imported)
        'importer': None,
        'importer_address': None,
        'consensus_hash': preorder_record['consensus_hash']
    }

    namespace_preorder_record = {
        "address": pybitcoin.script_hex_to_address( namespace_record['sender'] ),
        "block_number": 373400,
        "consensus_hash": "1c54465d3486f07be2c7a81af0ef44ad",
        "fee": 6160,
        "preorder_hash": namespace_id_hash,
        "op": NAMESPACE_PREORDER,
        "op_fee": 40000000,
        "sender": namespace_record['sender'],
        "sender_pubkey": namespace_record['sender_pubkey'],
        "txid": namespace_record['namespace_id'],
        "vtxindex": 3
    }

    name_update_op = {
        'op': NAME_UPDATE,
        'op_fee': 6140,
        'vtxindex': 4,
        'txid': '0e0a3ed6145b6424267ae042911fbfc69e21a17d8c579ac9b114ba934ccda950',
        'block_number': 373701,
        'consensus_hash': '4017d71d6c5e87c9efe8633f1dc1c425',
        'name_hash': hash256_trunc128( name_record['name'] + '4017d71d6c5e87c9efe8633f1dc1c425' ),
        'value_hash': '11' * 20,
    }

    cur = db.cursor()
    print "namespace preorder"
    namedb_preorder_insert( cur, namespace_preorder_record )
    db.commit()
    
    print "namespace reveal"
    ns_preorder_rec = namedb_get_preorder( cur, namespace_preorder_record['preorder_hash'], namespace_preorder_record['block_number'] )
    namedb_state_create( cur, "NAMESPACE_REVEAL", namespace_record, namespace_record['reveal_block'], namespace_record['vtxindex'], namespace_record['txid'], namespace_record['namespace_id'], ns_preorder_rec, "namespaces" )
    db.commit()
    
    print "name preorder"
    namedb_preorder_insert( cur, preorder_record )
    db.commit()

    print "name register"
    nm_preorder_rec = namedb_get_preorder( cur, preorder_record['preorder_hash'], preorder_record['block_number'] )
    print "preorder:\n%s\n" % json.dumps(nm_preorder_rec, indent=4)
    namedb_state_create( cur, "NAME_REGISTRATION", name_record, name_record['block_number'], name_record['vtxindex'], name_record['txid'], name_record['name'], nm_preorder_rec, 'name_records' )
    db.commit()

    print "name update"
    nm_rec = namedb_get_name( cur, name_record['name'], current_block=name_record['block_number'] )
    print "register:\n%s\n" % json.dumps(nm_rec, indent=4)
    namedb_state_transition( cur, "NAME_UPDATE", name_update_op, name_update_op['block_number'], name_update_op['vtxindex'], name_update_op['txid'], name_record['name'], name_record, 'name_records' )
    db.commit()

    nm_rec = namedb_get_name( cur, name_record['name'], current_block=name_record['block_number'] )
    print "after update:\n%s\n" % json.dumps(nm_rec, indent=4)

    print "\nhistory:\n"
    hist = namedb_get_history( cur, name )
    print json.dumps( hist, indent=4 )

    db.close()

