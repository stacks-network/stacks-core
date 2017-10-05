#!/usr/bin/env python2
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

import os
import sys
import shutil
import tempfile
import base64
import keylib
import urllib
import hashlib
import tarfile

import virtualchain
from virtualchain.lib.ecdsalib import sign_digest, verify_digest

log = virtualchain.get_logger("blockstack-server")

import nameset.virtualchain_hooks as virtualchain_hooks

import config

from .b40 import *
from .config import *
from .scripts import *
from .hashing import *
from .storage import *

from .nameset import *
from .operations import *

def snapshot_peek_number( fd, off ):
    """
    Read the last 8 bytes of fd
    and interpret it as an int.
    """
    # read number of 8 bytes 
    fd.seek( off - 8, os.SEEK_SET )
    value_hex = fd.read(8)
    if len(value_hex) != 8:
        return None
    try:
        value = int(value_hex, 16)
    except ValueError:
        return None

    return value


def snapshot_peek_sigb64( fd, off, bytelen ):
    """
    Read the last :bytelen bytes of
    fd and interpret it as a base64-encoded
    string
    """
    fd.seek( off - bytelen, os.SEEK_SET )
    sigb64 = fd.read(bytelen)
    if len(sigb64) != bytelen:
        return None

    try:
        base64.b64decode(sigb64)
    except:
        return None

    return sigb64


def get_file_hash( fd, hashfunc, fd_len=None ):
    """
    Get the hex-encoded hash of the fd's data
    """

    h = hashfunc()
    fd.seek(0, os.SEEK_SET)

    count = 0
    while True:
        buf = fd.read(65536)
        if len(buf) == 0:
            break

        if fd_len is not None:
            if count + len(buf) > fd_len:
                buf = buf[:fd_len - count]

        h.update(buf)
        count += len(buf)

    hashed = h.hexdigest()
    return hashed


def fast_sync_sign_snapshot( snapshot_path, private_key, first=False ):
    """
    Append a signature to the end of a snapshot path
    with the given private key.

    If first is True, then don't expect the signature trailer.

    Return True on success
    Return False on error
    """
   
    if not os.path.exists(snapshot_path):
        log.error("No such file or directory: {}".format(snapshot_path))
        return False

    file_size = 0
    payload_size = 0
    write_offset = 0
    try:
        sb = os.stat(snapshot_path)
        file_size = sb.st_size
        assert file_size > 8
    except Exception as e:
        log.exception(e)
        return False
    
    num_sigs = 0
    snapshot_hash = None
    with open(snapshot_path, 'r+') as f:

        if not first:
            info = fast_sync_inspect(f)
            if 'error' in info:
                log.error("Failed to inspect {}: {}".format(snapshot_path, info['error']))
                return False

            num_sigs = len(info['signatures'])
            write_offset = info['sig_append_offset']
            payload_size = info['payload_size']
 
        else:
            # no one has signed yet.
            write_offset = file_size
            num_sigs = 0
            payload_size = file_size

        # hash the file and sign the (bin-encoded) hash
        privkey_hex = keylib.ECPrivateKey(private_key).to_hex()
        hash_hex = get_file_hash( f, hashlib.sha256, fd_len=payload_size )
        sigb64 = sign_digest( hash_hex, privkey_hex, hashfunc=hashlib.sha256 )
      
        if os.environ.get("BLOCKSTACK_TEST") == "1":
            log.debug("Signed {} with {} to make {}".format(hash_hex, keylib.ECPrivateKey(private_key).public_key().to_hex(), sigb64))

        # append
        f.seek(write_offset, os.SEEK_SET)
        f.write(sigb64)
        f.write('{:08x}'.format(len(sigb64)))

        # append number of signatures
        num_sigs += 1
        f.write('{:08x}'.format(num_sigs))
    
        f.flush()
        os.fsync(f.fileno())

    return True


def fast_sync_snapshot_compress( snapshot_dir, export_path ):
    """
    Given the path to a directory, compress it and export it to the
    given path.

    Return {'status': True} on success
    Return {'error': ...} on failure
    """

    snapshot_dir = os.path.abspath(snapshot_dir)
    export_path = os.path.abspath(export_path)
    if os.path.exists(export_path):
        return {'error': 'Snapshot path exists: {}'.format(export_path)}

    old_dir = os.getcwd()
    
    count_ref = [0]

    def print_progress(tarinfo):
        count_ref[0] += 1
        if count_ref[0] % 100 == 0:
            log.debug("{} files...".format(count_ref[0]))

        return tarinfo

    try:
        os.chdir(snapshot_dir)
        with tarfile.TarFile.bz2open(export_path, "w") as f:
            f.add(".", filter=print_progress)

    except:
        os.chdir(old_dir)
        raise
    
    finally:
        os.chdir(old_dir)

    return {'status': True}


def fast_sync_snapshot_decompress( snapshot_path, output_dir ):
    """
    Given the path to a snapshot file, decompress it and 
    write its contents to the given output directory

    Return {'status': True} on success
    Return {'error': ...} on failure
    """
    if not tarfile.is_tarfile(snapshot_path):
        return {'error': 'Not a tarfile-compatible archive: {}'.format(snapshot_path)}

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with tarfile.TarFile.bz2open(snapshot_path, 'r') as f:
        tarfile.TarFile.extractall(f, path=output_dir)

    return {'status': True}


def fast_sync_snapshot( export_path, private_key, block_number ):
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
            shutil.rmtree(path)
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

        log.debug("Copy {} ({} bytes)".format(path, sb.st_size))


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
            for name in names:
                if name == 'zonefile.txt':
                    inner.zonefile_count += 1
                    if inner.zonefile_count % 100 == 0:
                        log.debug("{} zone files copied".format(inner.zonefile_count))
        
            return []

        inner.zonefile_count = 0
        return inner

    _zonefile_copy_progress = _zonefile_copy_progress_outer()

    # make sure we have the apppriate tools
    tools = ['sqlite3']
    for tool in tools:
        rc = os.system("which {} > /dev/null".format(tool))
        if rc != 0:
            log.error("'{}' command not found".format(tool))
            return False

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

    log.debug("Snapshot from block {}".format(block_number))

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
    res = fast_sync_snapshot_compress(tmpdir, export_path)
    if 'error' in res:
        log.error("Faield to compress {} to {}: {}".format(tmpdir, export_path, res['error']))
        _cleanup(tmpdir)
        return False

    log.debug("Wrote {} bytes".format(os.stat(export_path).st_size))

    # sign
    rc = fast_sync_sign_snapshot( export_path, private_key, first=True )
    if not rc:
        log.error("Failed to sign snapshot {}".format(export_path))
        return False

    _cleanup(tmpdir)
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
    
    log.debug("Fetch {} to {}...".format(import_url, tmppath))

    try:
        path, headers = urllib.urlretrieve(import_url, tmppath)
    except Exception, e:
        os.close(fd)
        log.exception(e)
        return None
    
    os.close(fd)
    return tmppath


def fast_sync_inspect( fd ):
    """
    Inspect a snapshot, given its file descriptor.
    Get the signatures and payload size
    Return {'status': True, 
            'signatures': signatures,
            'payload_size': payload size,
            'sig_append_offset': offset} on success
    Return {'error': ...} on error
    """
    sb = os.fstat(fd.fileno())
    ptr = sb.st_size
    if ptr < 8:
        log.debug("fd is {} bytes".format(ptr))
        return {'error': 'File is too small to be a snapshot'}

    signatures = []
    sig_append_offset = 0
    
    fd.seek(0, os.SEEK_SET)

    # read number of signatures
    num_signatures = snapshot_peek_number(fd, ptr)
    if num_signatures is None or num_signatures > 256:
        log.error("Unparseable num_signatures field")
        return {'error': 'Unparseable num_signatures'}

    # consumed
    ptr -= 8

    # future signatures get written here
    sig_append_offset = ptr

    # read signatures
    for i in xrange(0, num_signatures):
        sigb64_len = snapshot_peek_number(fd, ptr)
        if sigb64_len is None or sigb64_len > 100:
            log.error("Unparseable signature length field")
            return {'error': 'Unparseable signature length'}

        # consumed length
        ptr -= 8

        sigb64 = snapshot_peek_sigb64(fd, ptr, sigb64_len)
        if sigb64 is None:
            log.error("Unparseable signature")
            return {'error': 'Unparseable signature'}

        # consumed signature
        ptr -= len(sigb64)

        signatures.append( sigb64 )

    return {'status': True, 'signatures': signatures, 'payload_size': ptr, 'sig_append_offset': sig_append_offset}


def fast_sync_inspect_snapshot( snapshot_path ):
    """
    Inspect a snapshot
    Return useful information
    Return {'status': True, 'signatures': ..., 'payload_size': ..., 'sig_append_offset': ..., 'hash': ...} on success
    Return {'error': ...} on error
    """
    with open(snapshot_path, 'r') as f:
        info = fast_sync_inspect( f )
        if 'error' in info:
            log.error("Failed to inspect snapshot {}: {}".format(import_path, info['error']))
            return {'error': 'Failed to inspect snapshot'}

        # get the hash of the file 
        hash_hex = get_file_hash(f, hashlib.sha256, fd_len=info['payload_size'])
        info['hash'] = hash_hex

    return info


def fast_sync_import( working_dir, import_url, public_keys=config.FAST_SYNC_PUBLIC_KEYS, num_required=len(config.FAST_SYNC_PUBLIC_KEYS), verbose=False ):
    """
    Fast sync import.
    Verify the given fast-sync file from @import_path using @public_key, and then 
    uncompress it into @working_dir.

    Verify that at least `num_required` public keys in `public_keys` signed.
    NOTE: `public_keys` needs to be in the same order as the private keys that signed.
    """

    def logmsg(s):
        if verbose:
            print s
        else:
            log.debug(s)

    def logerr(s):
        if verbose:
            print >> sys.stderr, s
        else:
            log.error(s)

    if working_dir is None:
        working_dir = virtualchain.get_working_dir()

    if not os.path.exists(working_dir):
        logerr("No such directory {}".format(working_dir))
        return False

    # go get it 
    import_path = fast_sync_fetch(import_url)
    if import_path is None:
        logerr("Failed to fetch {}".format(import_url))
        return False

    # format: <signed bz2 payload> <sigb64> <sigb64 length (8 bytes hex)> ... <num signatures>
    file_size = 0
    try:
        sb = os.stat(import_path)
        file_size = sb.st_size
    except Exception as e:
        log.exception(e)
        return False

    num_signatures = 0
    ptr = file_size
    signatures = []

    with open(import_path, 'r') as f:
        info = fast_sync_inspect( f )
        if 'error' in info:
            logerr("Failed to inspect snapshot {}: {}".format(import_path, info['error']))
            return False

        signatures = info['signatures']
        ptr = info['payload_size']

        # get the hash of the file 
        hash_hex = get_file_hash(f, hashlib.sha256, fd_len=ptr)
        
        # validate signatures over the hash
        logmsg("Verify {} bytes".format(ptr))
        key_idx = 0
        num_match = 0
        for next_pubkey in public_keys:
            for sigb64 in signatures:
                valid = verify_digest( hash_hex, keylib.ECPublicKey(next_pubkey).to_hex(), sigb64, hashfunc=hashlib.sha256 ) 
                if valid:
                    num_match += 1
                    if num_match >= num_required:
                        break
                    
                    logmsg("Public key {} matches {} ({})".format(next_pubkey, sigb64, hash_hex))
                    signatures.remove(sigb64)
                
                else:
                    logmsg("Public key {} does NOT match {} ({})".format(next_pubkey, sigb64, hash_hex))

        # enough signatures?
        if num_match < num_required:
            logerr("Not enough signatures match (required {}, found {})".format(num_required, num_match))
            return False

    # decompress
    import_path = os.path.abspath(import_path)
    res = fast_sync_snapshot_decompress(import_path, working_dir)
    if 'error' in res:
        logerr("Failed to decompress {} to {}: {}".format(import_path, working_dir, res['error']))
        return False

    # restore from backup
    rc = blockstack_backup_restore(working_dir, None)
    if not rc:
        logerr("Failed to instantiate blockstack name database")
        return False

    # success!
    logmsg("Restored to {}".format(working_dir))
    return True


def blockstack_backup_restore( working_dir, block_number ):
    """
    Restore the database from a backup in the backups/ directory.
    If block_number is None, then use the latest backup.

    NOT THREAD SAFE

    Return True on success
    Return False on failure
    """

    # TODO: this is pretty shady...
    def _set_working_dir(wd):
        old_working_dir = os.environ.get('VIRTUALCHAIN_WORKING_DIR', None)
        if wd is not None:
            os.environ['VIRTUALCHAIN_WORKING_DIR'] = wd

        return old_working_dir

    old_working_dir = _set_working_dir(working_dir)

    if block_number is None:
        all_blocks = BlockstackDB.get_backup_blocks( virtualchain_hooks )
        if len(all_blocks) == 0:
            log.error("No backups available")
    
            # TODO: this is pretty shady...
            _set_working_dir(old_working_dir)
            return False

        block_number = max(all_blocks)

    found = True
    backup_paths = BlockstackDB.get_backup_paths( block_number, virtualchain_hooks )
    for p in backup_paths:
        if not os.path.exists(p):
            log.error("Missing backup file: '%s'" % p)
            found = False

    if not found:

        # TODO: this is pretty shady...
        _set_working_dir(old_working_dir)
        return False 

    rc = BlockstackDB.backup_restore( block_number, virtualchain_hooks )
    if not rc:
        log.error("Failed to restore backup")

        # TODO: this is pretty shady...
        _set_working_dir(old_working_dir)
        return False

    log.debug("Restored backup from {}".format(block_number))

    # TODO: this is pretty shady...
    _set_working_dir(old_working_dir)

    return True

