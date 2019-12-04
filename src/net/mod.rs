/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

pub mod asn;
pub mod chat;
pub mod codec;
pub mod connection;
pub mod db;
pub mod neighbors;
pub mod p2p;
pub mod poll;
pub mod prune;

use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::error;
use std::io;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use burnchains::BurnchainHeaderHash;

use chainstate::burn::ConsensusHash;
use chainstate::burn::CONSENSUS_HASH_ENCODED_SIZE;
use chainstate::burn::BlockHeaderHash;

use chainstate::stacks::StacksBlock;
use chainstate::stacks::StacksMicroblock;
use chainstate::stacks::StacksTransaction;

use util::hash::DoubleSha256;
use util::hash::Hash160;
use util::hash::DOUBLE_SHA256_ENCODED_SIZE;
use util::hash::HASH160_ENCODED_SIZE;

use util::db::Error as db_error;
use util::db::DBConn;

use util::log;

use util::secp256k1::Secp256k1PublicKey;
use util::secp256k1::MessageSignature;
use util::secp256k1::MESSAGE_SIGNATURE_ENCODED_SIZE;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Failed to encode
    SerializeError,
    /// Failed to decode 
    DeserializeError,
    /// Failed to recognize message
    UnrecognizedMessageID,
    /// Underflow -- not enough bytes to form the message
    UnderflowError,
    /// Overflow -- message too big 
    OverflowError,
    /// Array is too big 
    ArrayTooLong,
    /// Receive timed out 
    RecvTimeout,
    /// Error signing a message
    SigningError(String),
    /// Error verifying a message 
    VerifyingError(String),
    /// Read stream is drained.  Try again
    TemporarilyDrained,
    /// Read stream has reached EOF (socket closed, end-of-file reached, etc.)
    PermanentlyDrained,
    /// Failed to read from the FS 
    FilesystemError,
    /// Database error 
    DBError,
    /// Socket mutex was poisoned
    SocketMutexPoisoned,
    /// Not connected to peer
    SocketNotConnectedToPeer,
    /// Connection is broken and ought to be re-established
    ConnectionBroken,
    /// Connection could not be (re-)established
    ConnectionError,
    /// Too many outgoing messages 
    OutboxOverflow,
    /// Too many incoming messages 
    InboxOverflow,
    /// Send error 
    SendError(String),
    /// Recv error 
    RecvError(String),
    /// Invalid message 
    InvalidMessage,
    /// Invalid network handle
    InvalidHandle,
    /// Invalid handshake 
    InvalidHandshake,
    /// Stale neighbor
    StaleNeighbor,
    /// No such neighbor 
    NoSuchNeighbor,
    /// Failed to bind
    BindError,
    /// Failed to poll 
    PollError,
    /// Failed to accept 
    AcceptError,
    /// Failed to register socket with poller 
    RegisterError,
    /// Failed to query socket metadata 
    SocketError,
    /// server is not bound to a socket
    NotConnected,
    /// Remote peer is not connected 
    PeerNotConnected,
    /// Too many peers
    TooManyPeers,
    /// Peer already connected 
    AlreadyConnected
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::SerializeError => f.write_str(error::Error::description(self)),
            Error::DeserializeError => f.write_str(error::Error::description(self)),
            Error::UnrecognizedMessageID => f.write_str(error::Error::description(self)),
            Error::UnderflowError => f.write_str(error::Error::description(self)),
            Error::OverflowError => f.write_str(error::Error::description(self)),
            Error::ArrayTooLong => f.write_str(error::Error::description(self)),
            Error::RecvTimeout => f.write_str(error::Error::description(self)),
            Error::SigningError(ref s) => fmt::Display::fmt(s, f),
            Error::VerifyingError(ref s) => fmt::Display::fmt(s, f),
            Error::TemporarilyDrained => f.write_str(error::Error::description(self)),
            Error::PermanentlyDrained => f.write_str(error::Error::description(self)),
            Error::FilesystemError => f.write_str(error::Error::description(self)),
            Error::DBError => f.write_str(error::Error::description(self)),
            Error::SocketMutexPoisoned | Error::SocketNotConnectedToPeer => f.write_str(error::Error::description(self)),
            Error::ConnectionBroken => f.write_str(error::Error::description(self)),
            Error::ConnectionError => f.write_str(error::Error::description(self)),
            Error::OutboxOverflow => f.write_str(error::Error::description(self)),
            Error::InboxOverflow => f.write_str(error::Error::description(self)),
            Error::SendError(ref s) => fmt::Display::fmt(s, f),
            Error::RecvError(ref s) => fmt::Display::fmt(s, f),
            Error::InvalidMessage => f.write_str(error::Error::description(self)),
            Error::InvalidHandle => f.write_str(error::Error::description(self)),
            Error::InvalidHandshake => f.write_str(error::Error::description(self)),
            Error::StaleNeighbor => f.write_str(error::Error::description(self)),
            Error::NoSuchNeighbor => f.write_str(error::Error::description(self)),
            Error::BindError => f.write_str(error::Error::description(self)),
            Error::PollError => f.write_str(error::Error::description(self)),
            Error::AcceptError => f.write_str(error::Error::description(self)),
            Error::RegisterError => f.write_str(error::Error::description(self)),
            Error::SocketError => f.write_str(error::Error::description(self)),
            Error::NotConnected => f.write_str(error::Error::description(self)),
            Error::PeerNotConnected => f.write_str(error::Error::description(self)),
            Error::TooManyPeers => f.write_str(error::Error::description(self)),
            Error::AlreadyConnected => f.write_str(error::Error::description(self)),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::SerializeError => None,
            Error::DeserializeError => None,
            Error::UnrecognizedMessageID => None,
            Error::UnderflowError => None,
            Error::OverflowError => None,
            Error::ArrayTooLong => None,
            Error::RecvTimeout => None,
            Error::SigningError(ref _s) => None,
            Error::VerifyingError(ref _s) => None,
            Error::TemporarilyDrained => None,
            Error::PermanentlyDrained => None,
            Error::FilesystemError => None,
            Error::DBError => None,
            Error::SocketMutexPoisoned | Error::SocketNotConnectedToPeer => None,
            Error::ConnectionBroken => None,
            Error::ConnectionError => None,
            Error::OutboxOverflow => None,
            Error::InboxOverflow => None,
            Error::SendError(ref _s) => None,
            Error::RecvError(ref _s) => None,
            Error::InvalidMessage => None,
            Error::InvalidHandle => None,
            Error::InvalidHandshake => None,
            Error::StaleNeighbor => None,
            Error::NoSuchNeighbor => None,
            Error::BindError => None,
            Error::PollError => None,
            Error::AcceptError => None,
            Error::RegisterError => None,
            Error::SocketError => None,
            Error::NotConnected => None,
            Error::PeerNotConnected => None,
            Error::TooManyPeers => None,
            Error::AlreadyConnected => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::SerializeError => "Failed to serialize message payload",
            Error::DeserializeError => "Failed to deserialize message payload",
            Error::UnrecognizedMessageID => "Failed to recognize message type",
            Error::UnderflowError => "Not enough remaining data to parse",
            Error::OverflowError => "Message is too long",
            Error::ArrayTooLong => "Array too long",
            Error::RecvTimeout => "Packet receive timeout",
            Error::SigningError(ref s) => s.as_str(),
            Error::VerifyingError(ref s) => s.as_str(),
            Error::TemporarilyDrained => "Temporarily out of bytes to read; try again later",
            Error::PermanentlyDrained => "Out of bytes to read",
            Error::FilesystemError => "Disk I/O error",
            Error::DBError => "Database error",
            Error::SocketMutexPoisoned => "socket mutex was poisoned",
            Error::SocketNotConnectedToPeer => "not connected to peer",
            Error::ConnectionBroken => "connection to peer node is broken",
            Error::ConnectionError => "connection to peer could not be (re-)established",
            Error::OutboxOverflow => "too many outgoing messages queued",
            Error::InboxOverflow => "too many messages pending",
            Error::SendError(ref s) => s.as_str(),
            Error::RecvError(ref s) => s.as_str(),
            Error::InvalidMessage => "invalid message (malformed or bad signature)",
            Error::InvalidHandle => "invalid network handle",
            Error::InvalidHandshake => "invalid handshake from remote peer",
            Error::StaleNeighbor => "neighbor is too far behind the chain tip",
            Error::NoSuchNeighbor => "no such neighbor",
            Error::BindError => "Failed to bind to the given address",
            Error::PollError => "Failed to poll",
            Error::AcceptError => "Failed to accept connection",
            Error::RegisterError => "Failed to register socket with poller",
            Error::SocketError => "Socket error",
            Error::NotConnected => "Not connected to peer network",
            Error::PeerNotConnected => "Remote peer is not connected to us",
            Error::TooManyPeers => "Too many peer connections open",
            Error::AlreadyConnected => "Peer already connected"
        }
    }
}

// helper trait for various primitive types that make up Stacks messages
pub trait StacksMessageCodec {
    fn serialize(&self) -> Vec<u8>
        where Self: Sized;
    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<Self, Error>
        where Self: Sized;
}

/// A container for an IPv4 or IPv6 address.
/// Rules:
/// -- If this is an IPv6 address, the octets are in network byte order
/// -- If this is an IPv4 address, the octets must encode an IPv6-to-IPv4-mapped address
pub struct PeerAddress([u8; 16]);
impl_array_newtype!(PeerAddress, u8, 16);
impl_array_hexstring_fmt!(PeerAddress);
impl_byte_array_newtype!(PeerAddress, u8, 16);
pub const PEER_ADDRESS_ENCODED_SIZE : u32 = 16;

impl PeerAddress {
    /// Is this an IPv4 address?
    pub fn is_ipv4(&self) -> bool {
        self.ipv4_octets().is_some()
    }
    
    /// Get the octet representation of this peer address as an IPv4 address.
    /// The last 4 bytes of the list contain the IPv4 address.
    /// This method returns None if the bytes don't encode a valid IPv4-mapped address (i.e. ::ffff:0:0/96)
    pub fn ipv4_octets(&self) -> Option<[u8; 4]> {
        if self.0[0..12] != [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff] {
            return None;
        }
        let mut ret = [0u8; 4];
        ret.copy_from_slice(&self.0[12..16]);
        Some(ret)
    }

    /// Return the bit representation of this peer address as an IPv4 address, in network byte
    /// order.  Return None if this is not an IPv4 address.
    pub fn ipv4_bits(&self) -> Option<u32> {
        let octets_opt = self.ipv4_octets();
        if octets_opt.is_none() {
            return None;
        }

        let octets = octets_opt.unwrap();
        Some(
            ((octets[0] as u32) << 24) | 
            ((octets[1] as u32) << 16) | 
            ((octets[2] as u32) << 8) |
            ((octets[3] as u32))
        )
    }

    /// Convert to SocketAddr
    pub fn to_socketaddr(&self, port: u16) -> SocketAddr {
        if self.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(self.0[12], self.0[13], self.0[14], self.0[15])), port)
        }
        else {
            let addr_words : [u16; 8] = [
                ((self.0[0] as u16) << 8) | (self.0[1] as u16),
                ((self.0[2] as u16) << 8) | (self.0[3] as u16),
                ((self.0[4] as u16) << 8) | (self.0[5] as u16),
                ((self.0[6] as u16) << 8) | (self.0[7] as u16),
                ((self.0[8] as u16) << 8) | (self.0[9] as u16),
                ((self.0[10] as u16) << 8) | (self.0[11] as u16),
                ((self.0[12] as u16) << 8) | (self.0[13] as u16),
                ((self.0[14] as u16) << 8) | (self.0[15] as u16)
            ];

            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(addr_words[0], addr_words[1], addr_words[2], addr_words[3], addr_words[4], addr_words[5], addr_words[6], addr_words[7])), port)
        }
    }

    /// Convert from socket address 
    pub fn from_socketaddr(addr: &SocketAddr) -> PeerAddress {
        match addr.ip() {
            IpAddr::V4(ref addr) => {
                let octets = addr.octets();
                PeerAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, octets[0], octets[1], octets[2], octets[3]])
            },
            IpAddr::V6(ref addr) => {
                let words = addr.segments();
                PeerAddress([(words[0] >> 8) as u8, (words[0] & 0xff) as u8,
                             (words[1] >> 8) as u8, (words[1] & 0xff) as u8,
                             (words[2] >> 8) as u8, (words[2] & 0xff) as u8,
                             (words[3] >> 8) as u8, (words[3] & 0xff) as u8,
                             (words[4] >> 8) as u8, (words[4] & 0xff) as u8,
                             (words[5] >> 8) as u8, (words[5] & 0xff) as u8,
                             (words[6] >> 8) as u8, (words[6] & 0xff) as u8,
                             (words[7] >> 8) as u8, (words[7] & 0xff) as u8])
            }
        }
    }

    /// Convert from ipv4 octets
    pub fn from_ipv4(o1: u8, o2: u8, o3: u8, o4: u8) -> PeerAddress {
        PeerAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, o1, o2, o3, o4])
    }
}

/// A container for public keys (compressed secp256k1 public keys)
pub struct StacksPublicKeyBuffer(pub [u8; 33]);
impl_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_array_hexstring_fmt!(StacksPublicKeyBuffer);
impl_byte_array_newtype!(StacksPublicKeyBuffer, u8, 33);

pub const STACKS_PUBLIC_KEY_ENCODED_SIZE : u32 = 33;

/// Message preamble -- included in all network messages
#[derive(Debug, Clone, PartialEq)]
pub struct Preamble {
    pub peer_version: u32,                          // software version
    pub network_id: u32,                            // mainnet, testnet, etc.
    pub seq: u32,                                   // message sequence number -- pairs this message to a request
    pub burn_block_height: u64,                     // last-seen block height (at chain tip)
    pub burn_consensus_hash: ConsensusHash,         // consensus hash at block_height
    pub burn_stable_block_height: u64,              // latest stable block height (e.g. chain tip minus 7)
    pub burn_stable_consensus_hash: ConsensusHash,  // consensus hash for burn_stable_block_height
    pub additional_data: u32,                       // RESERVED; pointer to additional data (should be all 0's if not used)
    pub signature: MessageSignature,                // signature from the peer that sent this
    pub payload_len: u32                            // length of the following payload, including relayers vector
}

// addands correspond to fields above
pub const PREAMBLE_ENCODED_SIZE: u32 = 
    4 +
    4 +
    4 +
    8 +
    CONSENSUS_HASH_ENCODED_SIZE +
    8 +
    CONSENSUS_HASH_ENCODED_SIZE +
    4 +
    MESSAGE_SIGNATURE_ENCODED_SIZE +
    4;

/// Request for a block inventory or a list of blocks
#[derive(Debug, Clone, PartialEq)]
pub struct GetBlocksData {
    pub burn_height_start: u64,
    pub burn_header_hash_start: BurnchainHeaderHash,
    pub burn_height_end: u64,
    pub burn_header_hash_end: BurnchainHeaderHash
}

/// The "stream tip" information about a block's trailer microblocks.
#[derive(Debug, Clone, PartialEq)]
pub struct MicroblocksInvData {
    pub last_microblock_hash: BlockHeaderHash,
    pub last_sequence: u8
}

/// A bit vector that describes which block and microblock data node has data for in a given burn
/// chain block range.  Sent in reply to a GetBlocksData.
#[derive(Debug, Clone, PartialEq)]
pub struct BlocksInvData {
    pub bitlen: u16,                            // number of bits represented in bitvec (not to exceed BLOCKS_INV_DATA_MAX_BITLEN)
    pub bitvec: Vec<u8>,                        // bitvec[0] & 0x01 is the _earliest_ block.  Has length = ceil(bitlen / 8)
    pub microblocks_inventory: Vec<MicroblocksInvData>  // each block's microblock inventories.  Has length = bitlen
}

/// List of blocks returned
#[derive(Debug, Clone, PartialEq)]
pub struct BlocksData {
    pub blocks: Vec<StacksBlock>
}

/// Get a batch of microblocks 
#[derive(Debug, Clone, PartialEq)]
pub struct GetMicroblocksData {
    pub burn_header_height: u64,
    pub burn_header_hash: BurnchainHeaderHash,
    pub block_header_hash: BlockHeaderHash,
    pub microblocks_header_hash: BlockHeaderHash
}

/// Microblocks batch (reply to GetMicroblcoks)
#[derive(Debug, Clone, PartialEq)]
pub struct MicroblocksData {
    pub microblocks: Vec<StacksMicroblock>
}

/// A descriptor of a peer
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NeighborAddress {
    pub addrbytes: PeerAddress,
    pub port: u16,
    pub public_key_hash: Hash160        // used as a hint; useful for when a node trusts another node to be honest about this
}

impl fmt::Display for NeighborAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}://{:?}:{}", &self.public_key_hash, &self.addrbytes, self.port)
    }
}

impl fmt::Debug for NeighborAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}://{:?}:{}", &self.public_key_hash, &self.addrbytes, self.port)
    }
}

pub const NEIGHBOR_ADDRESS_ENCODED_SIZE : u32 =
    PEER_ADDRESS_ENCODED_SIZE +
    2 +
    HASH160_ENCODED_SIZE;

/// A descriptor of a list of known peers
#[derive(Debug, Clone, PartialEq)]
pub struct NeighborsData {
    pub neighbors: Vec<NeighborAddress>
}

/// Handshake request -- this is the first message sent to a peer.
/// The remote peer will reply a HandshakeAccept with just a preamble
/// if the peer accepts.  Otherwise it will get a HandshakeReject with just
/// a preamble.
///
/// To keep peer knowledge fresh, nodes will send handshakes to each other
/// as heartbeat messages.
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeData {
    pub addrbytes: PeerAddress,
    pub port: u16,
    pub services: u16,                          // bit field representing services this node offers
    pub node_public_key: StacksPublicKeyBuffer,
    pub expire_block_height: u64,               // burn block height after which this node's key will be revoked
}

#[repr(C)]
pub enum ServiceFlags {
    RELAY = 0x01,
    RPC = 0x02,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeAcceptData {
    pub handshake: HandshakeData,       // this peer's handshake information
    pub heartbeat_interval: u32,        // hint as to how long this peer will remember you

    // TODO: string with useful data (e.g. RPC endpoints)
}

#[derive(Debug, Clone, PartialEq)]
pub struct NackData {
    pub error_code: u32,
}
pub mod NackErrorCodes {
    pub const HandshakeRequired : u32 = 1;
}

#[derive(Debug, Clone, PartialEq)]
pub struct PingData {
    pub nonce: u32
}

#[derive(Debug, Clone, PartialEq)]
pub struct PongData {
    pub nonce: u32
}

#[derive(Debug, Clone, PartialEq)]
pub struct RelayData {
    pub peer: NeighborAddress,
    pub seq: u32,
    pub signature: MessageSignature
}
pub const RELAY_DATA_ENCODED_SIZE : u32 =
    NEIGHBOR_ADDRESS_ENCODED_SIZE +
    4 +
    MESSAGE_SIGNATURE_ENCODED_SIZE;

#[derive(Debug, Clone, PartialEq)]
pub enum StacksMessageType {
    Handshake(HandshakeData),
    HandshakeAccept(HandshakeAcceptData),
    HandshakeReject,
    GetNeighbors,
    Neighbors(NeighborsData),
    GetBlocksInv(GetBlocksData),
    BlocksInv(BlocksInvData),
    GetBlocks(GetBlocksData),
    Blocks(BlocksData),
    GetMicroblocks(GetMicroblocksData),
    Microblocks(MicroblocksData),
    Transaction(StacksTransaction),
    Nack(NackData),
    Ping(PingData),
    Pong(PongData)
}

// I would do this as an enum, but there's no easy way to match on an enum's numeric representation
pub mod StacksMessageID {
    pub const Handshake : u8 = 0;
    pub const HandshakeAccept : u8 = 1;
    pub const HandshakeReject : u8 = 2;
    pub const GetNeighbors : u8 = 3;
    pub const Neighbors : u8 = 4;
    pub const GetBlocksInv : u8 = 5;
    pub const BlocksInv : u8 = 6;
    pub const GetBlocks : u8 = 7;
    pub const Blocks : u8 = 8;
    pub const GetMicroblocks : u8 = 9;
    pub const Microblocks : u8 = 10;
    pub const Transaction : u8 = 11;
    pub const Nack : u8 = 12;
    pub const Ping : u8 = 13;
    pub const Pong : u8 = 14;
    pub const Reserved : u8 = 255;
}

/// Container for all Stacks network messages
#[derive(Debug, Clone, PartialEq)]
pub struct StacksMessage {
    pub preamble: Preamble,
    pub relayers: Vec<RelayData>,
    pub payload: StacksMessageType,
}

// an array in our protocol can't exceed this many items
pub const ARRAY_MAX_LEN : u32 = u32::max_value();

// maximum number of neighbors in a NeighborsData
pub const MAX_NEIGHBORS_DATA_LEN : u32 = 128;

// maximum number of relayers -- will be an upper bound on the peer graph diameter
pub const MAX_RELAYERS_LEN : u32 = 16;

// messages can't be bigger than 16MB plus the preamble and relayers
pub const MAX_MESSAGE_LEN : u32 = (1 + 16 * 1024 * 1024) + (PREAMBLE_ENCODED_SIZE + MAX_RELAYERS_LEN * RELAY_DATA_ENCODED_SIZE);

// maximum length of a microblock's hash list
pub const MICROBLOCKS_INV_DATA_MAX_HASHES : u32 = 4096;

// maximum value of a blocks's inv data bitlen 
pub const BLOCKS_INV_DATA_MAX_BITLEN : u32 = 4096;

// heartbeat threshold -- start trying to ping a node at this many seconds before expiration
pub const HEARTBEAT_PING_THRESHOLD : u64 = 600;

macro_rules! impl_byte_array_message_codec {
    ($thing:ident, $len:expr) => {
        impl StacksMessageCodec for $thing {
            fn serialize(&self) -> Vec<u8> {
                self.as_bytes().to_vec()
            }
            fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<$thing, ::net::Error> {
                let index = *index_ptr;
                if index > u32::max_value() - ($len) {
                    return Err(::net::Error::OverflowError);
                }
                if index + ($len) > max_size {
                    return Err(::net::Error::OverflowError);
                }
                if (buf.len() as u32) < index + ($len) {
                    return Err(::net::Error::UnderflowError);
                }
                let ret = $thing::from_bytes(&buf[(index as usize)..((index+($len)) as usize)])
                    .ok_or(::net::Error::UnderflowError)?;

                *index_ptr += $len;
                Ok(ret)
            }
        }
    }
}

impl_byte_array_message_codec!(ConsensusHash, 20);
impl_byte_array_message_codec!(DoubleSha256, 32);
impl_byte_array_message_codec!(Hash160, 20);
impl_byte_array_message_codec!(BurnchainHeaderHash, 32);
impl_byte_array_message_codec!(BlockHeaderHash, 32);
impl_byte_array_message_codec!(MessageSignature, 65);
impl_byte_array_message_codec!(PeerAddress, 16);
impl_byte_array_message_codec!(StacksPublicKeyBuffer, 33);

/// neighbor identifier 
#[derive(Clone, Eq)]
pub struct NeighborKey {
    pub peer_version: u32,
    pub network_id: u32,
    pub addrbytes: PeerAddress,
    pub port: u16,
}

impl Hash for NeighborKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // ignores peer version and network ID -- we don't accept or deal with messages that have
        // incompatible versions or network IDs in the first place
        self.addrbytes.hash(state);
        self.port.hash(state);
    }
}

impl PartialEq for NeighborKey {
    fn eq(&self, other: &NeighborKey) -> bool {
        // peer version doesn't count 
        self.network_id == other.network_id && self.addrbytes == other.addrbytes && self.port == other.port
    }
}

impl fmt::Display for NeighborKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let peer_version_str = if self.peer_version > 0 { format!("{:08x}", self.peer_version).to_string() } else { "UNKNOWN".to_string() };
        let network_id_str = if self.network_id > 0 { format!("{:08x}", self.network_id).to_string() } else { "UNKNOWN".to_string() };
        write!(f, "{}+{}://{:?}:{}", peer_version_str, network_id_str, &self.addrbytes, self.port)
    }
}

impl fmt::Debug for NeighborKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let peer_version_str = if self.peer_version > 0 { format!("{:08x}", self.peer_version).to_string() } else { "UNKNOWN".to_string() };
        let network_id_str = if self.network_id > 0 { format!("{:08x}", self.network_id).to_string() } else { "UNKNOWN".to_string() };
        write!(f, "{}+{}://{:?}:{}", peer_version_str, network_id_str, &self.addrbytes, self.port)
    }
}

/// Entry in the neighbor set
#[derive(Debug, Clone, PartialEq)]
pub struct Neighbor {
    pub addr: NeighborKey,
    
    // fields below this can change at runtime
    pub public_key: Secp256k1PublicKey,
    pub expire_block: u64,
    pub last_contact_time: u64,
    
    pub whitelisted: i64,       // whitelist deadline (negative == "forever")
    pub blacklisted: i64,       // blacklist deadline (negative == "forever")

    pub asn: u32,               // AS number
    pub org: u32,               // organization identifier

    pub in_degree: u32,         // number of peers who list this peer as a neighbor
    pub out_degree: u32,        // number of neighbors this peer has
}

pub const NUM_NEIGHBORS : usize = 32;

#[cfg(test)]
mod test {
    use super::*;
    use net::asn::*;
    use net::chat::*;
    use net::connection::*;
    use net::codec::*;
    use net::db::*;
    use net::neighbors::*;
    use net::p2p::*;
    use net::poll::*;
    use net::Error as net_error;

    use chainstate::burn::*;
    use chainstate::burn::db::burndb;
    use chainstate::burn::db::burndb::*;
    use chainstate::*;

    use burnchains::*;
    use burnchains::burnchain::*;

    use burnchains::bitcoin::*;
    use burnchains::bitcoin::address::*;
    use burnchains::bitcoin::keys::*;
    
    use util::secp256k1::*;
    use util::hash::*;
    use util::uint::*;

    use std::net::*;
    use std::io;
    use std::io::Read;
    use std::io::Write;
    use std::io::ErrorKind;
    use std::io::Cursor;
    use std::ops::Deref;
    use std::ops::DerefMut;
    use std::collections::HashMap;

    pub struct NetCursor<T> {
        c: Cursor<T>,
    }

    impl<T> NetCursor<T> {
        pub fn new(inner: T) -> NetCursor<T> {
            NetCursor {
                c: Cursor::new(inner)
            }
        }
    }

    impl<T> Deref for NetCursor<T> {
        type Target = Cursor<T>;
        fn deref(&self) -> &Cursor<T> {
            &self.c
        }
    }
    
    impl<T> DerefMut for NetCursor<T> {
        fn deref_mut(&mut self) -> &mut Cursor<T> {
            &mut self.c
        }
    }

    impl<T> Read for NetCursor<T>
    where
        T: AsRef<[u8]>
    {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let sz = self.c.read(buf)?;
            if sz == 0 {
                // when reading from a non-blocking socket, a return value of 0 indicates the
                // remote end was closed.  For this reason, when we're out of bytes to read on our
                // inner cursor, we need to re-interpret this as EWOULDBLOCK.
                return Err(io::Error::from(ErrorKind::WouldBlock));
            }
            else {
                return Ok(sz);
            }
        }
    }

    impl Write for NetCursor<&mut [u8]> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.c.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.c.flush()
        }
    }
    
    impl Write for NetCursor<&mut Vec<u8>> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.c.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.c.flush()
        }
    }
    
    impl Write for NetCursor<Vec<u8>> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.c.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.c.flush()
        }
    }

    // describes a peer's initial configuration
    #[derive(Debug, Clone)]
    pub struct TestPeerConfig {
        pub current_block: u64,
        pub private_key: Secp256k1PrivateKey,
        pub private_key_expire: u64,
        pub initial_neighbors: Vec<Neighbor>,
        pub asn4_entries: Vec<ASEntry4>,
        pub burnchain: Burnchain,
        pub connection_opts: ConnectionOptions,
        pub server_port: u16,
        pub asn: u32,
        pub org: u32,
        pub whitelisted: i64,
        pub blacklisted: i64
    }

    impl TestPeerConfig {
        pub fn default() -> TestPeerConfig {
            let conn_opts = ConnectionOptions::default();
            let start_block = 10000;
            let burnchain = Burnchain::default_unittest(start_block, &BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap());
            TestPeerConfig {
                current_block: start_block + (burnchain.consensus_hash_lifetime + 1) as u64,
                private_key: Secp256k1PrivateKey::new(),
                private_key_expire: start_block + conn_opts.private_key_lifetime,
                initial_neighbors: vec![],
                asn4_entries: vec![],
                burnchain: burnchain,
                connection_opts: conn_opts,
                server_port: 32000,
                asn: 0,
                org: 0,
                whitelisted: 0,
                blacklisted: 0
            }
        }

        pub fn from_port(p: u16) -> TestPeerConfig {
            TestPeerConfig {
                server_port: p,
                ..TestPeerConfig::default()
            }
        }

        pub fn add_neighbor(&mut self, n: &Neighbor) -> () {
            self.initial_neighbors.push(n.clone());
        }

        pub fn to_neighbor(&self) -> Neighbor {
            Neighbor {
                addr: NeighborKey {
                    peer_version: self.burnchain.peer_version,
                    network_id: self.burnchain.network_id,
                    addrbytes: PeerAddress([0,0,0,0,0,0,0,0,0,0,0xff,0xff,127,0,0,1]),
                    port: self.server_port
                },
                public_key: Secp256k1PublicKey::from_private(&self.private_key),
                expire_block: self.private_key_expire,

                // not known yet
                last_contact_time: 0,
                whitelisted: self.whitelisted,
                blacklisted: self.blacklisted,
                asn: self.asn,
                org: self.org,
                in_degree: 0,
                out_degree: 0
            }
        }
    }

    pub struct TestPeer {
        pub config: TestPeerConfig,
        pub network: PeerNetwork,
        pub burndb: Option<BurnDB>
    }

    pub fn u64_to_bytes(i: u64) -> [u8; 8] {
        [
            (i & 0xff00000000000000) as u8,
            (i & 0x00ff000000000000) as u8,
            (i & 0x0000ff0000000000) as u8,
            (i & 0x000000ff00000000) as u8,
            (i & 0x00000000ff000000) as u8,
            (i & 0x0000000000ff0000) as u8,
            (i & 0x000000000000ff00) as u8,
            (i & 0x00000000000000ff) as u8
        ]
    }

    impl TestPeer {
        pub fn new(config: &TestPeerConfig) -> TestPeer {
            let mut peerdb = PeerDB::connect_memory(config.burnchain.network_id, config.private_key_expire, &config.asn4_entries, &config.initial_neighbors).unwrap();
            let mut burndb = BurnDB::connect_memory(config.burnchain.first_block_height, &config.burnchain.first_block_hash).unwrap();

            {
                let mut tx = burndb.tx_begin().unwrap();
                let mut prev_snapshot = BurnDB::get_first_block_snapshot(&tx).unwrap();
                for i in prev_snapshot.block_height..config.current_block {
                    let mut next_snapshot = prev_snapshot.clone();

                    next_snapshot.block_height += 1;
                    
                    let big_i = Uint256::from_u64(i as u64);
                    let mut big_i_bytes_32 = [0u8; 32];
                    big_i_bytes_32.copy_from_slice(&big_i.to_u8_slice());

                    next_snapshot.consensus_hash = ConsensusHash(Hash160::from_sha256(&big_i_bytes_32).into_bytes());

                    next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
                    next_snapshot.burn_header_hash = BurnchainHeaderHash(big_i_bytes_32.clone());
                    next_snapshot.ops_hash = OpsHash::from_bytes(&big_i_bytes_32).unwrap();
                    next_snapshot.total_burn += 1;
                    next_snapshot.num_sortitions += 1;
                    next_snapshot.sortition = true;
                    next_snapshot.sortition_hash = next_snapshot.sortition_hash.mix_burn_header(&BurnchainHeaderHash(big_i_bytes_32.clone()));

                    let next_index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &prev_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
                    next_snapshot.index_root = next_index_root;
                    prev_snapshot = next_snapshot;
                }
                tx.commit().unwrap();
            }

            let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), config.server_port);

            {
                let mut tx = peerdb.tx_begin().unwrap();
                PeerDB::set_local_ipaddr(&mut tx, &PeerAddress::from_socketaddr(&local_addr), config.server_port).unwrap();
                PeerDB::set_local_services(&mut tx, ServiceFlags::RELAY as u16).unwrap();
                PeerDB::set_local_private_key(&mut tx, &config.private_key, config.private_key_expire).unwrap();
                
                tx.commit().unwrap();
            }
            
            let mut peer_network = PeerNetwork::new(peerdb, &config.burnchain, &config.connection_opts);

            peer_network.bind(&local_addr).unwrap();
            
            TestPeer {
                config: (*config).clone(),
                network: peer_network,
                burndb: Some(burndb)
            }
        }

        pub fn connect_initial(&mut self) -> Result<(), net_error> {
            let local_peer = PeerDB::get_local_peer(self.network.peerdb.conn()).unwrap();
            let chain_view = match self.burndb {
                Some(ref mut burndb) => {
                    let mut tx = burndb.tx_begin().unwrap();
                    BurnDB::get_burnchain_view(&mut tx, &self.config.burnchain).unwrap()
                }
                None => panic!("Misconfigured peer: no burndb")
            };

            for n in self.config.initial_neighbors.iter() {
                self.network.connect_peer(&local_peer, &chain_view, &n.addr)
                    .and_then(|e| Ok(()))?;
            }
            Ok(())
        }

        pub fn step(&mut self) -> Result<HashMap<NeighborKey, Vec<StacksMessage>>, net_error> {
            let mut burndb = self.burndb.take().unwrap();
            let burnchain_snapshot = {
                let mut tx = burndb.tx_begin().unwrap();
                BurnDB::get_burnchain_view(&mut tx, &self.config.burnchain).unwrap()
            };
            let ret = self.network.run(&burnchain_snapshot, 1);
            self.burndb = Some(burndb);
            ret
        }

        pub fn empty_burnchain_block(&self, block_height: u64) -> BurnchainBlock {
            assert!(block_height + 1 >= self.config.burnchain.first_block_height);
            let prev_block_height = block_height - 1;

            let block_hash_i = Uint256::from_u64(block_height);
            let mut block_hash_bytes = [0u8; 32];
            block_hash_bytes.copy_from_slice(&block_hash_i.to_u8_slice());
            
            let prev_block_hash_i = Uint256::from_u64(prev_block_height);
            let mut prev_block_hash_bytes = [0u8; 32];
            prev_block_hash_bytes.copy_from_slice(&prev_block_hash_i.to_u8_slice());

            BurnchainBlock::Bitcoin(BitcoinBlock {
                block_height: block_height + 1,
                block_hash: BurnchainHeaderHash(block_hash_bytes),
                parent_block_hash: BurnchainHeaderHash(prev_block_hash_bytes),
                txs: vec![]
            })
        }

        pub fn next_burnchain_block(&mut self, block: &BurnchainBlock) -> () {
            let mut burndb = self.burndb.take().unwrap();
            Burnchain::process_block(&mut burndb, &self.config.burnchain, block).unwrap();
            self.burndb = Some(burndb);
        }

        pub fn add_empty_burnchain_block(&mut self) -> u64 {
            let empty_block = {
                let burndb = self.burndb.take().unwrap();
                let sn = BurnDB::get_canonical_burn_chain_tip(burndb.conn()).unwrap();
                let empty_block = self.empty_burnchain_block(sn.block_height);
                self.burndb = Some(burndb);
                empty_block
            };
            self.next_burnchain_block(&empty_block);
            empty_block.block_height()
        }

        pub fn to_neighbor(&self) -> Neighbor {
            self.config.to_neighbor()
        }

        pub fn get_public_key(&self) -> Secp256k1PublicKey {
            let local_peer = PeerDB::get_local_peer(&self.network.peerdb.conn()).unwrap();
            Secp256k1PublicKey::from_private(&local_peer.private_key)
        }

        pub fn get_peerdb_conn(&self) -> &DBConn {
            self.network.peerdb.conn()
        }

        pub fn dump_frontier(&self) -> () {
            let conn = self.network.peerdb.conn();
            let peers = PeerDB::get_all_peers(conn).unwrap();
            test_debug!("--- BEGIN ALL PEERS ({}) ---", peers.len());
            test_debug!("{:#?}", &peers);
            test_debug!("--- END ALL PEERS ({}) -----", peers.len());
        }
    }
}
