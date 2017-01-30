#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016-2017 by Blockstack.org

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

import logging
import os
import sys
import json
import datetime
import traceback
import time
import math
import random
import shutil
import tempfile
import binascii
import copy
import threading
import errno
import base64
import keylib
import subprocess
import urllib

import virtualchain
import blockstack_client

log = virtualchain.get_logger("blockstack-server")

import pybitcoin

import nameset as blockstack_state_engine
import nameset.virtualchain_hooks as virtualchain_hooks

import config

from .b40 import *
from .config import *
from .scripts import *
from .hashing import *
from .storage import *

from .nameset import *
from .operations import *


def sqlite3_backup( src_path, dest_path ):
    """
    Back up a sqlite3 database, while ensuring
    that no ongoing queries are being executed.

    Return True on success
    Return False on error.
    """

    # find sqlite3
    path = os.environ.get("PATH", None)
    if path is None:
        path = "/usr/local/bin:/usr/bin:/bin"

    sqlite3_path = None
    dirs = path.split(":")
    for pathdir in dirs:
        if len(pathdir) == 0:
            continue

        sqlite3_path = os.path.join(pathdir, 'sqlite3')
        if not os.path.exists(sqlite3_path):
            continue

        if not os.path.isfile(sqlite3_path):
            continue

        if not os.access(sqlite3_path, os.X_OK):
            continue

        break

    if sqlite3_path is None:
        log.error("Could not find sqlite3 binary")
        return False

    sqlite3_cmd = [sqlite3_path, src_path, '.backup "{}"'.format(dest_path)]
    rc = None
    try:
        log.debug("{}".format(" ".join(sqlite3_cmd)))
        p = subprocess.Popen(sqlite3_cmd, shell=False, close_fds=True)
        rc = p.wait()
    except Exception, e:
        log.exception(e)
        return False

    if not os.WIFEXITED(rc):
        # bad exit 
        log.error("{} exit code {:x}".format(sqlite3_path, rc))
        return False
    
    if os.WEXITSTATUS(rc) != 0:
        # bad exit
        log.error("{} exited {}".format(sqlite3_path, rc))
        return False

    return True


def fast_sync_snapshot( export_path, private_key, working_dir, block_number ):
    """
    Export all the local state for fast-sync.
    If block_number is given, then the name database
    at that particular block number will be taken.

    The exported tarball will be signed with the given private key,
    and the signature will be appended to the end of the file.

    Return True if we succeed
    Return False if not
    """

    db_paths = None
    found = True
    tmpdir = None
    namedb_path = None

    def _cleanup(path):
        try:
            # shutil.rmtree(path)
            print 'rm -rf {}'.format(path)
        except Exception, e:
            log.exception(e)
            log.error("Failed to clear directory {}".format(path))

    
    def _log_backup(path):
        sb = None
        try:
            sb = os.stat(path)
        except Exception, e:
            log.exception(e)
            log.error("Failed to stat {}".format(path))
            return False

        log.debug("Back up {} ({} bytes)".format(path, sb.st_size))


    def _copy_paths(src_paths, dest_dir):
        for db_path in src_paths:
            dest_path = os.path.join(dest_dir, os.path.basename(db_path))
            try:
                _log_backup(db_path)
                shutil.copy(db_path, dest_path)
            except Exception, e:
                log.exception(e)
                log.error("Failed to copy {} to {}".format(db_path, dest_path))
                return False
        
        return True


    # ugly hack to work around the lack of a `nonlocal` keyword in Python 2.x
    def _zonefile_copy_progress_outer():
        def inner(src, names):
            for _ in names:
                inner.zonefile_count += 1
                if inner.zonefile_count % 100 == 0:
                    log.debug("{} zone files copied".format(zonefile_count))
        
            return []

        inner.zonefile_count = 0
        return inner

    _zonefile_copy_progress = _zonefile_copy_progress_outer()

    # make sure we have the apppriate tools
    tools = ['tar', 'bzip2', 'mv', 'sqlite3']
    for tool in tools:
        rc = os.system("which {} > /dev/null".format(tool))
        if rc != 0:
            log.error("'{}' command not found".format(tool))
            return False

    if working_dir is None:
        working_dir = virtualchain.get_working_dir() 

    if not os.path.exists(working_dir):
        log.error("No such directory {}".format(working_dir))
        return False

    if block_number is None:
        # last backup
        all_blocks = BlockstackDB.get_backup_blocks( virtualchain_hooks )
        if len(all_blocks) == 0:
            log.error("No backups available")
            return False

        block_number = max(all_blocks)

    # use a backup database 
    db_paths = BlockstackDB.get_backup_paths( block_number, virtualchain_hooks )

    for p in db_paths:
        if not os.path.exists(p):
            log.error("Missing file: '%s'" % p)
            found = False

    if not found:
        return False

    try:
        tmpdir = tempfile.mkdtemp(prefix='.blockstack-export-')
    except Exception, e:
        log.exception(e)
        return False

    # copying from backups 
    backups_path = os.path.join(tmpdir, "backups")
    try:
        os.makedirs(backups_path)
    except Exception, e:
        log.exception(e)
        log.error("Failed to make directory {}".format(backups_path))
        _cleanup(tmpdir)
        return False

    rc = _copy_paths(db_paths, backups_path)
    if not rc:
        _cleanup(tmpdir)
        return False

    # copy over atlasdb
    atlasdb_path = os.path.join(working_dir, "atlas.db")
    dest_path = os.path.join(tmpdir, "atlas.db")
    _log_backup(atlasdb_path)
    rc = sqlite3_backup(atlasdb_path, dest_path)
    if not rc:
        _cleanup(tmpdir)
        return False

    # copy over zone files
    zonefiles_path = os.path.join(working_dir, "zonefiles")
    dest_path = os.path.join(tmpdir, "zonefiles")
    try:
        shutil.copytree(zonefiles_path, dest_path, ignore=_zonefile_copy_progress)
    except Exception, e:
        log.exception(e)
        log.error('Failed to copy {} to {}'.format(zonefiles_path, dest_path))
        return False

    # compress
    export_path = os.path.abspath(export_path)
    cmd = "cd '{}' && tar cf 'snapshot.tar' * && bzip2 'snapshot.tar' && mv 'snapshot.tar.bz2' '{}'".format(tmpdir, export_path)
    log.debug("Compressing: {}".format(cmd))
    rc = os.system(cmd)
    if rc != 0:
        log.exception("Failed to compress {}. Exit code {}. Command: \"{}\"".format(tmpdir, rc, cmd))
        _cleanup(tmpdir)
        return False

    log.debug("Wrote {} bytes".format(os.stat(export_path).st_size))

    # sign the payload and append the signature
    with open(export_path, 'a+') as f:
        sigb64 = blockstack_client.sign_file_data(f, keylib.ECPrivateKey(private_key).to_hex())
        f.write(sigb64)
        f.write("{:08x}".format(len(sigb64)))

    return True


def fast_sync_fetch( import_url ):
    """
    Get the data for an import snapshot.
    Store it to a temporary path
    Return the path on success
    Return None on error
    """
    try:
        fd, tmppath = tempfile.mkstemp(prefix='.blockstack-fast-sync-')
    except Exception, e:
        log.exception(e)
        return None
    
    try:
        path, headers = urllib.urlretrieve(import_url, tmppath)
    except Exception, e:
        os.close(fd)
        log.exception(e)
        return None
    
    os.close(fd)
    return tmppath


def fast_sync_import( working_dir, import_url, public_key=config.FAST_SYNC_PUBLIC_KEY ):
    """
    Fast sync import.
    Verify the given fast-sync file from @import_path using @public_key, and then 
    uncompress it into @working_dir
    """

    # make sure we have the apppriate tools
    tools = ['tar', 'bzip2', 'mv']
    for tool in tools:
        rc = os.system("which {} > /dev/null".format(tool))
        if rc != 0:
            log.error("'{}' command not found".format(tool))
            return False

    if working_dir is None:
        working_dir = virtualchain.get_working_dir()

    if not os.path.exists(working_dir):
        log.error("No such directory {}".format(working_dir))
        return False

    # go get it 
    import_path = fast_sync_fetch(import_url)
    if import_path is None:
        log.error("Failed to fetch {}".format(import_url))
        return False

    # format: <signed bz2 payload> <sigb64> <sigb64 length (8 bytes hex)>
    file_size = 0
    try:
        sb = os.stat(import_path)
        file_size = sb.st_size
    except Exception as e:
        log.exception(e)
        return False

    with open(import_path, 'r') as f:
        f.seek(file_size - 8, os.SEEK_SET)
        sigb64_len_hex = f.read(8)

        try:
            sigb64_len = int(sigb64_len_hex, 16)
        except ValueError:
            log.error("Unreasonable signature length field: {}".format(sigb64_len_hex))
            return False

        # reasonable?
        if sigb64_len > 100 or sigb64_len < 0:
            log.error("Unreasoanble signature length value {}".format(sigb64_len))
            return False

        f.seek(file_size - 8 - sigb64_len, os.SEEK_SET)
        sigb64 = f.read(sigb64_len)
        
        if len(sigb64) != sigb64_len:
            log.error("Invalid signature length {}".format(sigb64_len))
            return False

        try:
            base64.b64decode(sigb64)
        except:
            log.error("Invalid signature")
            return False

        f.seek(0, os.SEEK_SET)

        valid = blockstack_client.verify_file_data(f, keylib.ECPublicKey(public_key).to_hex(), sigb64, fd_len=(file_size - 8 - sigb64_len))
        if not valid:
            log.error("Unverifiable fast-sync data ({} bytes checked)".format(file_size - 8 - sigb64_len))
            return False

    # decompress
    import_path = os.path.abspath(import_path)
    cmd = "cd '{}' && tar xf '{}'".format(working_dir, import_path)
    log.debug(cmd)
    rc = os.system(cmd)
    if rc != 0:
        log.error("Failed to decompress. Exit code {}. Command: {}".format(rc, cmd))
        return False

    # restore from backup
    rc = blockstack_backup_restore(working_dir, None)
    if not rc:
        log.error("Failed to instantiate blockstack name database")
        return False

    # success!
    return True


def blockstack_backup_restore( working_dir, block_number ):
    """
    Restore the database from a backup in the backups/ directory.
    If block_number is None, then use the latest backup.
    Return True on success
    Return False on failure
    """

    if block_number is None:
        all_blocks = BlockstackDB.get_backup_blocks( virtualchain_hooks )
        if len(all_blocks) == 0:
            log.error("No backups available")
            return False

        block_number = max(all_blocks)

    found = True
    backup_paths = BlockstackDB.get_backup_paths( block_number, virtualchain_hooks )
    for p in backup_paths:
        if not os.path.exists(p):
            log.error("Missing backup file: '%s'" % p)
            found = False

    if not found:
        return False 

    rc = BlockstackDB.backup_restore( block_number, virtualchain_hooks )
    if not rc:
        log.error("Failed to restore backup")
        return False

    return True

