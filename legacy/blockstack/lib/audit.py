#!/usr/bin/env python2
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
import jsonschema
import json
import hashlib
import os
import subprocess
import virtualchain
import tempfile
import shutil

from .schemas import  GENESIS_BLOCK_SCHEMA
from .genesis_block import GENESIS_BLOCK_SIGNING_KEYS

log = virtualchain.get_logger('audit')

def find_gpg2():
    # need gpg2 to be installed 
    gpg2_path = None
    p = subprocess.Popen('which gpg2', stdout=subprocess.PIPE, shell=True)
    out, _ = p.communicate()
    if p.returncode != 0:
        log.error('which gpg2 returned {}'.format(p.returncode))
        return None

    gpg2_path = out.strip()
    return gpg2_path


def load_signing_keys(gpg2_path, keys):
    # load a list of keys into gpg 
    for key in keys:
        p = subprocess.Popen([gpg2_path, '--import'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(key)
        if p.returncode != 0:
            log.error('Failed to import key\n{}'.format(err))
            return False

    return True


def check_gpg2_keys(gpg2_path, key_ids):
    # make sure each key ID is present in the user's GPG directory.
    # if not, try to load them.
    p = subprocess.Popen([gpg2_path, '--list-keys'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        log.error('Failed to list keys')
        return False

    missing = []
    for key_id in key_ids:
        if key_id.startswith('0x'):
            key_id = key_id[2:]

        found = False
        for line in out.split('\n'):
            line = line.strip()
            line_parts = line.split()
            for part in line_parts:
                # look for rsaXXXX/{:key_id} or dsaXXXX/{:key_id}
                if part.endswith('{}'.format(key_id.upper())):
                    found = True
                    break

        if not found:
            log.error('No key found: {}'.format(key_id))
            missing.append(key_id)

    if len(missing) > 0:
        log.error('Missing keys {}'.format(', '.join(missing)))
        return False

    return True


def genesis_block_audit(genesis_block_stages, key_bundle=GENESIS_BLOCK_SIGNING_KEYS):
    """
    Verify the authenticity of the stages of the genesis block, optionally with a given set of keys.
    Return True if valid
    Return False if not
    """
    gpg2_path = find_gpg2()
    if gpg2_path is None:
        raise Exception('You must install gpg2 to audit the genesis block, and it must be in your PATH')

    log.debug('Loading {} signing key(s)...'.format(len(key_bundle)))
    res = load_signing_keys(gpg2_path, [key_bundle[kid] for kid in key_bundle])
    if not res:
        raise Exception('Failed to install signing keys')

    log.debug('Verifying {} signing key(s)...'.format(len(key_bundle)))
    res = check_gpg2_keys(gpg2_path, key_bundle.keys())
    if not res:
        raise Exception('Failed to verify installation of signing keys')

    d = tempfile.mkdtemp(prefix='.genesis-block-audit-')

    # each entry in genesis_block_stages is a genesis block with its own history 
    for stage_id, stage in enumerate(genesis_block_stages):
        log.debug('Verify stage {}'.format(stage_id))

        try:
            jsonschema.validate(GENESIS_BLOCK_SCHEMA, stage)
        except jsonschema.ValidationError:
            shutil.rmtree(d)
            log.error('Invalid genesis block -- does not match schema')
            raise ValueError('Invalid genesis block')

        # all history rows must be signed with a trusted key
        for history_id, history_row in enumerate(stage['history']):
            with open(os.path.join(d, 'sig'), 'w') as f:
                f.write(history_row['signature'])
            with open(os.path.join(d, 'hash'), 'w') as f:
                f.write(history_row['hash'])

            p = subprocess.Popen([gpg2_path, '--verify', os.path.join(d,'sig'), os.path.join(d,'hash')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            if p.returncode != 0:
                log.error('Failed to verify stage {} history {}'.format(stage_id, history_id))
                shutil.rmtree(d)
                return False

        gb_rows_str = json.dumps(stage['rows'], sort_keys=True, separators=(',',':')) + '\n'
        gb_rows_hash = hashlib.sha256(gb_rows_str).hexdigest()

        # must match final history row 
        if gb_rows_hash != stage['history'][-1]['hash']:
            log.error('Genesis block stage {} hash mismatch: {} != {}'.format(stage_id, gb_rows_hash, stage['history'][-1]['hash']))
            shutil.rmtree(d)
            return False

    shutil.rmtree(d)
    log.info('Genesis block is legitimate')
    return True
