# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2018 by Blockstack.org

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

import sqlite3
import traceback
import os
import json
import base64
import time
import random
import threading

from util import db_query_execute

QUEUE_SQL = """
CREATE TABLE IF NOT EXISTS queue( name STRING NOT NULL,
                                  queue_id STRING NOT NULL,
                                  data NOT NULL );
"""

from virtualchain import get_logger

log = get_logger()

DB_SERIALIZE_LOCK = threading.Lock()

def queuedb_create(path):
    """
    Create a sqlite3 db at the given path.
    Create all the tables and indexes we need.
    Raises if the table already exists
    """
    
    global QUEUE_SQL, ERROR_SQL

    lines = [l + ";" for l in QUEUE_SQL.split(";")]
    con = sqlite3.connect( path, isolation_level=None )

    for line in lines:
        db_query_execute(con, line, ())

    con.commit()
    con.row_factory = queuedb_row_factory
    return con


def queuedb_open(path):
    """
    Open a connection to the given database.
    hack: At most one queue-open can happen globally.
    """
    with DB_SERIALIZE_LOCK:
        return queuedb_create( path )


def queuedb_row_factory(cursor, row):
    """
    Dict row factory
    """
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]

    return d


def queuedb_query_execute(cur, query, values):
    """
    Execute a query.  If it fails, abort the program.
    Gracefully handle lock contention by timing out.
    """
    return db_query_execute(cur, query, values)


def queuedb_find(path, queue_id, name, offset=None, limit=None):
    """
    Find a record by name and queue ID.
    Return the rows on success (empty list if not found)
    Raise on error
    """
    return queuedb_findall(path, queue_id, name=name, offset=offset, limit=limit)


def queuedb_findall(path, queue_id, name=None, offset=None, limit=None):
    """
    Get all queued entries for a queue and a name.
    If name is None, then find all queue entries

    Return the rows on success (empty list if not found)
    Raise on error
    """
    sql = "SELECT * FROM queue WHERE queue_id = ? ORDER BY rowid ASC"
    args = (queue_id,)
    
    if name:
        sql += ' AND name = ?'
        args += (name,)

    if limit:
        sql += ' LIMIT ?'
        args += (limit,)
    
    if offset:
        sql += ' OFFSET ?'
        args += (offset,)

    sql += ';'
    
    db = queuedb_open(path)
    if db is None:
        raise Exception("Failed to open %s" % path)

    cur = db.cursor()
    rows = queuedb_query_execute(cur, sql, args)

    count = 0
    ret = []
    for row in rows:
        dat = {}
        dat.update(row)
        ret.append(dat)

    db.close()
    return ret


def queuedb_append(path, queue_id, name, data):
    """
    Append an element to the back of the queue.
    Return True on success
    Raise on error
    """
    sql = "INSERT INTO queue VALUES (?,?,?);"
    args = (name, queue_id, data)

    db = queuedb_open(path)
    if db is None:
        raise Exception("Failed to open %s" % path)

    cur = db.cursor()
    res = queuedb_query_execute(cur, sql, args)

    db.commit()
    db.close()
    return True


def queuedb_remove(path, entry, cur=None):
    """
    Remove an element from a queue.
    Return True on success
    Raise on error
    """
    sql = "DELETE FROM queue WHERE queue_id = ? AND name = ?;"
    args = (entry['queue_id'], entry['name'])

    cursor = None
    if cur:
        cursor = cur
    else:
        db = queuedb_open(path)
        if db is None:
            raise Exception("Failed to open %s" % path)

        cursor = db.cursor()

    res = queuedb_query_execute(cursor, sql, args)

    if cur is None:
        db.commit()
        db.close()

    return True


def queuedb_removeall(path, entries):
    """
    Remove all entries from a queue
    """
    db = queuedb_open(path)
    if db is None:
        raise Exception("Failed to open %s" % path)

    cursor = db.cursor()
    queuedb_query_execute(cursor, 'BEGIN', ())

    for entry in entries:
        queuedb_remove(path, entry, cur=cursor)

    queuedb_query_execute(cursor, 'END', ())
    db.commit()
    db.close()

    return True


def queuedb_peek(path, queue_id, name):
    """
    Find the oldest instance of a named record in a queue.
    """
    return queuedb_find(path, queue_id, name, limit=1)
