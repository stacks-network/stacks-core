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

import logging
import os
import zlib

if os.environ.get("BLOCKSTACK_DEBUG", None) is not None:
    DEBUG = True
else:
    DEBUG = False

def get_logger(name=None):
    """
    Get logger
    """

    level = logging.CRITICAL
    if DEBUG:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"
        level = logging.CRITICAL

    log = logging.getLogger(name=name)
    log.setLevel( level )
    console = logging.StreamHandler()
    console.setLevel( level )
    log_format = ('[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] (' + str(os.getpid()) + ') %(message)s' if DEBUG else '%(message)s')
    formatter = logging.Formatter( log_format )
    console.setFormatter(formatter)
    log.propagate = False

    if len(log.handlers) > 0:
        for i in xrange(0, len(log.handlers)):
            log.handlers.pop(0)
    
    log.addHandler(console)
    return log


def compress_chunk( chunk_buf ):
    """
    compress a chunk of data
    """
    data = zlib.compress(chunk_buf, 9)
    return data


def decompress_chunk( chunk_buf ):
    """
    decompress a chunk of data
    """
    data = zlib.decompress(chunk_buf)
    return data


def get_driver_settings_dir(config_path, driver_name):
    """
    driver-specific state
    """
    return os.path.join( os.path.dirname(config_path), "drivers/{}".format(driver_name))


def setup_scratch_space(scratch_dir):
    """
    Set up download scratch space
    Return True on success
    Return False on error
    """
    if not os.path.exists(scratch_dir):
        try:
            os.makedirs(scratch_dir)
            os.chmod(scratch_dir, 0700)
        except Exception as e:
            if DEBUG:
                log.exception(e)

            log.error("Failed to create scratch directory")
            return False

    else:
        # make sure we have the right mode 
        sb = os.stat(scratch_dir)
        if sb.st_mode != 0700:
            os.chmod(scratch_dir, 0700)

        # clear it out
        for name in os.listdir(scratch_dir):
            fp = os.path.join(scratch_dir, name)
            try:
                os.unlink(fp)
            except:
                pass

    return True


def make_scratch_file(dirp):
    """
    Make a scratch file at a given path.
    Return the path
    """
    scratch_fd, scratch_path = tempfile.mkstemp(dir=dirp)
    os.close(scratch_fd)
    return scratch_path

