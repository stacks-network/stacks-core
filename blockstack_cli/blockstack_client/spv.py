#!/usr/bin/python
"""
    Parts of this source file are derived from code from Electrum
    (https://github.com/spesmilo/electrum), as of December 9, 2015.

    These parts are (c) 2015 by Thomas Voegtlin.  All changes are
    subject to the following copyright.
"""
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


import socket
import os
import sys
import time
from config import log
from protocoin.clients import *
from protocoin.serializers import *
from protocoin.fields import *

import virtualchain
import pybitcoin
import bitcoin

BLOCK_HEADER_SIZE = 81
GENESIS_BLOCK_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
BLOCK_DIFFICULTY_CHUNK_SIZE = 2016
BLOCK_DIFFICULTY_INTERVAL = 14*24*60*60  # two weeks, in seconds
GENESIS_BLOCK_MERKLE_ROOT = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"


class BlockHash(object):
    """
    Block hash to request
    """
    def __init__(self, block_hash ):
        self.block_hash = block_hash 

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, "%064x" % self.block_hash)


class GetHeaders(object):
    """
    getheaders message
    """
    def __init__(self):
        self.block_hashes = []
        self.hash_stop = None
        self.command = "getheaders"

    def add_block_hash( self, block_hash ):
        """
        Append up to 2000 block hashes for which to get headers.
        """
        if len(self.block_hashes) > 2000:
            raise Exception("A getheaders request cannot have over 2000 block hashes")

        hash_num = int("0x" + block_hash, 16)
        self.block_hashes.append( BlockHash(hash_num) )
        self.hash_stop = hash_num

    def num_block_hashes( self ):
        """
        Get the number of block headers to request
        """
        return len(self.block_hashes)

    def __repr__(self):
        return "<%s block_hashes=[%s]>" % (self.__class__.__name__, ",".join([str(h) for h in self.block_hashes]))


class BlockHashSerializer( Serializer ):
    """
    Serialization class for a BlockHash
    """
    model_class = BlockHash
    block_hash = Hash()


class GetHeadersSerializer( Serializer ):
    """
    Serialization class for a GetHeaders
    """
    model_class = GetHeaders
    version = UInt32LEField()
    block_hashes = ListField(BlockHashSerializer)
    hash_stop = Hash()


class BlockHeaderClient( BitcoinBasicClient ):
    """
    Client to fetch and store block headers.
    """

    def __init__(self, socket, headers_path ):
        super(BlockHeaderClient, self).__init__(socket)
        self.path = headers_path
   

    def hash_to_string( self, hash_int ):
        return "%064x" % hash_int 


    def handle_headers( self, message_header, block_headers_message ):
        """
        Handle a 'headers' message.
        NOTE: we request headers in order, so we will expect to receive them in order here.
        Verify that we do so.
        """
        block_headers = block_headers_message.headers
        current_height = SPVClient.height( self.path )
        log.debug("Receive %s headers (%s to %s)" % (len(block_headers), current_height, current_height + len(block_headers)))

        serializer = BlockHeaderSerializer()

        # verify that the local header chain connects to this sequence
        last_header = SPVClient.read_header( self.path, current_height )

        if last_header['hash'] != self.hash_to_string(block_headers[0].prev_block):
            raise Exception("Received discontinuous block header '%s' (expected '%s')" % \
                    (self.hash_to_string(block_headers[0].prev_block),
                    last_header['hash'] ))

        # verify that this sequence of headers constitutes a hash chain 
        for i in xrange(1, len(block_headers)):
            prev_block_hash = self.hash_to_string(block_headers[i].prev_block)
            if prev_block_hash != block_headers[i-1].calculate_hash():
                raise Exception("Block '%s' is not continuous with block '%s'" % \
                        prev_block_hash,
                        block_headers[i-1].calculate_hash())

        # insert into to local headers database
        next_block_id = current_height + 1
        for block_header in block_headers:
            with open(self.path, "r+") as f:

                # omit tx count 
                block_header.txns_count = 0
                bin_data = serializer.serialize( block_header )

                if len(bin_data) != BLOCK_HEADER_SIZE:
                    raise Exception("Block %s (%s) has %s-byte header" % (next_block_id, block_header.calculate_hash(), len(bin_data)))

                # NOTE: the fact that we use seek + write ensures that we can:
                # * restart synchronizing at any point
                # * allow multiple processes to work on the chain safely (even if they're duplicating effort)
                f.seek( BLOCK_HEADER_SIZE * next_block_id, os.SEEK_SET )
                f.write( bin_data )

                next_block_id += 1
            
        
    def send_getheaders( self, prev_block_hash ):
        """
        Request block headers from a particular block hash.
        Will receive up to 2000 blocks, starting with the block *after*
        the given block hash (prev_block_hash)
        """
        getheaders = GetHeaders()
        getheaders_serial = GetHeadersSerializer()

        getheaders.add_block_hash( prev_block_hash )
        getheaders.version = PROTOCOL_VERSION

        self.send_message( getheaders, getheaders_serial )


    def handshake(self):
        """
        This method will implement the handshake of the
        Bitcoin protocol. It will send the Version message.
        """
        version = Version()
        version_serial = VersionSerializer()
        self.send_message(version, version_serial)


    def handle_version(self, message_header, message):
        """
        This method will handle the Version message and
        will send a VerAck message when it receives the
        Version message.

        :param message_header: The Version message header
        :param message: The Version message
        """
        verack = VerAck()
        verack_serial = VerAckSerializer()
        self.send_message(verack, verack_serial)


    def handle_ping(self, message_header, message):
        """
        This method will handle the Ping message and then
        will answer every Ping message with a Pong message
        using the nonce received.

        :param message_header: The header of the Ping message
        :param message: The Ping message
        """
        pong = Pong()
        pong_serial = PongSerializer()
        pong.nonce = message.nonce
        self.send_message(pong, pong_serial)    



class SPVClient(object):
    """
    Simplified Payment Verification client.
    Accesses locally-stored headers obtained by BlockHeaderClient
    to verify and synchronize them with the blockchain.
    """

    def __init__(self, path):
        SPVClient.init( path )


    @classmethod
    def init(cls, path):
        """
        Set up an SPV client.
        If the locally-stored headers do not exist, then 
        create a stub headers file with the genesis block information.
        """
        if not os.path.exists( path ):

            block_header_serializer = BlockHeaderSerializer()
            genesis_block_header = BlockHeader()
            genesis_block_header.version = 1
            genesis_block_header.prev_block = 0
            genesis_block_header.merkle_root = int(GENESIS_BLOCK_MERKLE_ROOT, 16 )
            genesis_block_header.timestamp = 1231006505
            genesis_block_header.bits = int( "1d00ffff", 16 )
            genesis_block_header.nonce = 2083236893
            genesis_block_header.txns_count = 0

            with open(path, "wb") as f:
                bin_data = block_header_serializer.serialize( genesis_block_header )
                f.write( bin_data )
            

    @classmethod
    def height(cls, path):
        """
        Get the locally-stored block height
        """
        if os.path.exists( path ):
            sb = os.stat( path )
            h = (sb.st_size / BLOCK_HEADER_SIZE) - 1
            return h
        else:
            return None


    @classmethod
    def read_header_at( cls, f ):
        """
        Given an open file-like object, read a block header
        from it and return it as a dict containing:
        * version (int)
        * prev_block_hash (hex str)
        * merkle_root (hex str)
        * timestamp (int)
        * bits (int)
        * nonce (ini)
        * hash (hex str)
        """
        header_parser = BlockHeaderSerializer()
        hdr = header_parser.deserialize( f )
        h = {}
        h['version'] = hdr.version
        h['prev_block_hash'] = "%064x" % hdr.prev_block
        h['merkle_root'] = "%064x" % hdr.merkle_root
        h['timestamp'] = hdr.timestamp
        h['bits'] = hdr.bits
        h['nonce'] = hdr.nonce
        h['hash'] = hdr.calculate_hash()
        return h


    @classmethod
    def load_header_chain( cls, chain_path ):
        """
        Load the header chain from disk.
        Each chain element will be a dictionary with:
        * 
        """

        header_parser = BlockHeaderSerializer()
        chain = []
        height = 0
        with open(chain_path, "rb") as f:

            h = SPVClient.read_header_at( f )
            h['block_height'] = height 

            height += 1
            chain.append(h)

        return chain


    @classmethod
    def read_header(cls, headers_path, block_height):
        """
        Get a block header at a particular height from disk.
        Return the header if found
        Return None if not.
        """
        if os.path.exists(headers_path):
    
            header_parser = BlockHeaderSerializer()
            sb = os.stat( headers_path )
            if sb.st_size < BLOCK_HEADER_SIZE * block_height:
                # beyond EOF 
                return None 

            with open( headers_path, "rb" ) as f:
                f.seek( block_height * BLOCK_HEADER_SIZE, os.SEEK_SET )
                hdr = SPVClient.read_header_at( f )

            return hdr
        else:
            return None


    @classmethod
    def get_target(cls, path, index, chain=None):
        """
        Calculate the target difficulty at a particular difficulty interval (index).
        Return (bits, target) on success
        """
        if chain is None:
            chain = []  # Do not use mutables as default values!

        max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        if index == 0:
            return 0x1d00ffff, max_target

        first = SPVClient.read_header( path, (index-1)*BLOCK_DIFFICULTY_CHUNK_SIZE)
        last = SPVClient.read_header( path, index*BLOCK_DIFFICULTY_CHUNK_SIZE - 1)
        if last is None:
            for h in chain:
                if h.get('block_height') == index*BLOCK_DIFFICULTY_CHUNK_SIZE - 1:
                    last = h

        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = BLOCK_DIFFICULTY_INTERVAL
        nActualTimespan = max(nActualTimespan, nTargetTimespan/4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan*4)

        bits = last.get('bits')
        # convert to bignum
        MM = 256*256*256
        a = bits%MM
        if a < 0x8000:
            a *= 256
        target = (a) * pow(2, 8 * (bits/MM - 3))

        # new target
        new_target = min( max_target, (target * nActualTimespan)/nTargetTimespan )

        # convert it to bits
        c = ("%064X"%new_target)[2:]
        i = 31
        while c[0:2]=="00":
            c = c[2:]
            i -= 1

        c = int('0x'+c[0:6],16)
        if c >= 0x800000:
            c /= 256
            i += 1

        new_bits = c + MM * i
        return new_bits, new_target

   
    @classmethod 
    def block_header_verify( cls, headers_path, block_id, block_hash, block_header ):
        """
        Given the block's numeric ID, its hash, and the bitcoind-returned block_data,
        use the SPV header chain to verify the block's integrity.

        block_header must be a dict with the following structure:
        * version: protocol version (int)
        * prevhash: previous block hash (hex str)
        * merkleroot: block Merkle root (hex str)
        * timestamp: UNIX time stamp (int)
        * bits: difficulty bits (hex str)
        * nonce: PoW nonce (int)
        * hash: block hash (hex str)
        (i.e. the format that the reference bitcoind returns via JSON RPC)

        Return True on success
        Return False on error
        """
        prev_header = cls.read_header( headers_path, block_id - 1 )
        prev_hash = prev_header['hash']
        return virtualchain.block_header_verify( block_header, prev_hash, block_hash )


    @classmethod 
    def block_verify( cls, verified_block_header, block_txids ):
        """
        Given the block's verified header structure (see block_header_verify) and
        its list of transaction IDs (as hex strings), verify that the transaction IDs are legit.

        Return True on success
        Return False on error.
        """

        block_data = {
            'merkleroot': verified_block_header['merkleroot'],
            'tx': block_txids
        }

        return virtualchain.block_verify( block_data )


    @classmethod 
    def tx_hash( cls, tx ):
        """
        Calculate the hash of a transction
        """
        tx_hex = virtualchain.tx_to_hex( tx )
        tx_hash = pybitcoin.bin_double_sha256(tx_hex.decode('hex'))[::-1].encode('hex')
        return tx_hash


    @classmethod
    def tx_verify( cls, verified_block_txids, tx ):
        """
        Given the block's verified block txids, verify that a transaction is legit.
        @tx must be a dict with the following fields:
        * locktime: int
        * version: int
        * vin: list of dicts with:
           * vout: int,
           * hash: hex str
           * sequence: int (optional)
           * scriptSig: dict with:
              * hex: hex str
        * vout: list of dicts with:
           * value: float
           * scriptPubKey: dict with:
              * hex: hex str
        """
        tx_hash = cls.tx_hash( tx )
        return tx_hash in verified_block_txids


    @classmethod 
    def tx_index( cls, verified_block_txids, verified_tx ):
        """
        Given a block's verified block txids and a verified transaction, 
        find out where it is in the list of txids (i.e. what's its index)?
        """
        tx_hash = cls.tx_hash( verified_tx )
        return verified_block_txids.index( tx_hash )


    @classmethod 
    def block_header_index( cls, path, block_header ):
        """
        Given a block's serialized header, go and find out what its
        block ID is (if it is present at all).

        Return the >= 0 index on success
        Return -1 if not found.

        NOTE: this is slow
        """
        with open( path, "r" ) as f:
            chain_raw = f.read()

        for blk in xrange(0, len(chain_raw) / (BLOCK_HEADER_SIZE)):
            if chain_raw[blk * BLOCK_HEADER_SIZE : blk * BLOCK_HEADER_SIZE + BLOCK_HEADER_SIZE] == block_header:
                return blk

        return -1


    @classmethod
    def verify_header_chain(cls, path, chain=None):
        """
        Verify that a given chain of block headers
        has sufficient proof of work.
        """
        if chain is None:
            chain = SPVClient.load_header_chain( path )

        prev_header = chain[0]
        
        for i in xrange(1, len(chain)):
            header = chain[i]
            height = header.get('block_height')
            prev_hash = prev_header.get('hash')
            if prev_hash != header.get('prev_block_hash'):
                log.error("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
                return False

            bits, target = SPVClient.get_target( path, height/BLOCK_DIFFICULTY_CHUNK_SIZE, chain)
            if bits != header.get('bits'):
                log.error("bits mismatch: %s vs %s" % (bits, header.get('bits')))
                return False

            _hash = header.get('hash')
            if int('0x'+_hash, 16) > target:
                log.error("insufficient proof of work: %s vs target %s" % (int('0x'+_hash, 16), target))
                return False

            prev_header = header

        return True


    @classmethod
    def sync_header_chain(cls, path, bitcoind_server, last_block_id ):
        """
        Synchronize our local block headers up to the last block ID given.
        """
        current_block_id = SPVClient.height( path )
        if current_block_id < last_block_id:
           
            log.debug("Synchronize %s to %s" % (current_block_id, last_block_id))

            # need to sync
            prev_block_header = SPVClient.read_header( path, current_block_id )
            prev_block_hash = prev_block_header['hash']

            # connect 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect( (bitcoind_server, 8333) )
            client = BlockHeaderClient( sock, path )
            client.handshake()

            # request first batch 
            client.send_getheaders( prev_block_hash )

            while True:

                # next message
                message_header, message = client.receive_message()

                if not message:
                    continue

                # dispatch message
                handle_func_name = "handle_" + message_header.command
                handle_func = getattr(client, handle_func_name, None)
                if handle_func:
                    handle_func(message_header, message)
               
                if message_header.command == "headers":
                    # got reply to our getheaders request.
                    # pipe the next one in
                    current_block_id = SPVClient.height( path )
                    prev_block_header = SPVClient.read_header( path, current_block_id )
                    prev_block_hash = prev_block_header['hash']
                    client.send_getheaders( prev_block_hash )

                # synchronized?
                if SPVClient.height( path ) >= last_block_id:
                    break

            # verify headers 
            rc = SPVClient.verify_header_chain( path )
            if not rc:
               raise Exception("Failed to verify headers (stored in '%s')" % path)

        return True


if __name__ == "__main__":
    # test synchonize headers 
    try:
        bitcoind_server = sys.argv[1]
        headers_path = sys.argv[2]
        height = int(sys.argv[3])
    except:
        print >> sys.stderr, "Usage: %s bitcoind_server headers_path blockchain_height" % sys.argv[0]
        sys.exit(0)

    SPVClient.init( headers_path )
    rc = SPVClient.sync_header_chain( headers_path, bitcoind_server, height )
    if rc:
        print "Headers are up to date with %s and seem to have sufficient proof-of-work" % height
