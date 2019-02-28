# SIP 003 Peer Network

## Preamble

Title: Peer Network

Author: Jude Nelson <jude@blockstack.com>

Status: Draft

Type: Standard

Created: 2/27/2018 

License: BSD 2-Clause

## Abstract

This SIP describes the design of the Stacks peer network, used for relaying
blocks, transactions, and routing information.  The document describes both the
overall protocol design and rationale, and provides descriptions of each
message's wire format (where applicable).

## Rationale

The Stacks blockchain implements a peer-to-peer _reachability network_ in order
to ensure that each Stacks peer has a full copy of all blocks committed to on
the burn chain, and all unconfirmed transactions.  A full replica of the chain
state is necessary for user security -- users must be able to determine what
their account states are in order to know that any transactions they send from
them are valid as they are sent.  In addition, a full replica of all chain state
is desirable from a reliability perspective -- as long as there exists one
available replica, then it will be possible for new peers to bootstrap
themselves from it and determine the current state of the chain.  As such, the
network protocol is designed to help peers build full replicas while remaining
resilient to disruptions and partitions.

The Stacks peer network is designed with the following design goals in mind:

* **Ease of reimplementation**.  The rules for encoding and decoding messages
  are meant to be as simple as possible to facilitate implementing ancilliary software
that depends on talking to the peer network.  Sacrificing a little bit of space
efficiency is acceptable if it makes encoding and decoding simpler.

* **Unstructured reachability**.  The peer network's routing algorithm
  prioritizes building a _random_ peer graph such that there are many
_distinct_ paths between any two peers.  A random (unstructured) graph is
preferred to a structured graph in order to maximize the number of neighbor peers that
a given peer will consider in its frontier.  When choosing neighbors, a peer
will prefer to maximize the number of _distinct_ autonomous systems represented
in its frontier in order to help keep as many networks on the Internet connected
to the Stacks peer network.

## Specification

The following subsections describe the data structures and protocols for the
Stacks peer network.  In particular, this document discusses _only_ the peer
network message sturcture and protocols.  It does _not_ document the structure
of Stacks transactions and blocks.  These structures will be defined in a future
SIP.

### Encoding Conventions

This section explains how this document will describe the Stacks messages, and
explains the conventions used to encode Stacks messages as a sequence of bytes.

All Stacks network messages are composed of _scalars_, _byte buffers_ of fixed
length, _vectors_ of variable length, and _typed containers_ of variable length.

A scalar is a number represnted by 1, 2, 4, or 8 bytes, and is unsigned.
Scalars requiring 2, 4, and 8 bytes are encoded in network byte order (i.e. big-endian).

Byte buffers have known length and are transmitted as-is.

Vectors are encoded as length-prefixed arrays.  The first 4 bytes of a vector
are a scalar that encodes the vector's length.  As such, a vector may not have
more than 2^32 - 1 items.  Vectors are recursively defined in terms of other 
scalars, byte buffers, vectors, and typed containers.

A typed container is encoded as a 1-byte type identifier, followed by zero or
more encoded structures.  Typed containers are used in practice to encode
type variants, such as types of message payloads or types of transactions.
Typed containers are recursively-defined in terms of other scalars, byte
buffers, vectors, and type containers.

**Example**

Consider the following message definitions:

```
// a byte buffer
pub struct SomeBytes([u8; 10]);

pub struct ExampleMessagePayload {
   pub aa: u16,
   pub bytes: SomeBytes
}

// will encode to a typed container
pub enum PayloadVariant {
   Foo(ExampleMessagePayload),
   Bar(u32)
}

pub const FOO_MESSAGE_TYPE_ID: u8 = 0x00;
pub const BAR_MESSAGE_TYPE_ID: u8 = 0x01;

// top-level message that will encode to a sequence of bytes
pub struct ExampleMessage {
   pub a: u8,
   pub b: u16,
   pub c: u32,
   pub d: u64,
   pub e: Vec<u64>,
   pub payload: PayloadVariant,
   pub payload_list: Vec<PayloadVariant>
}
```

Consider the following instantiation of an `ExampleMessage` on a little-endian
machine (such as an Intel x86):

```
pub msg = ExampleMessage {
   a: 0x80,
   b: 0x9091,
   c: 0xa0a1a2a3,
   d: 0xb0b1b2b3b4b5b6b7,
   e: vec![0xc0c1c2c3c4c5c6c7, 0xd0d1d2d3d4d5d6d7, 0xe0e1e2e3e4e5e6e7],
   payload: PayloadVariant::Foo(
      ExampleMessagePayload {
         aa: 0xaabb,
         bytes: SomeBytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
      }
   ),
   payload_list: vec![
      PayloadVariant::Foo(
         ExampleMessagePayload {
            aa: 0xccdd,
            bytes: SomeBytes([0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13])
         }
      ),
      PayloadVariant::Bar(0x00112233)
   ]
};
```

This message would serialize to the following bytes.  Note that each line represents 
a separate record to improve readability.

```
80                               # msg.a
91 90                            # msg.b in network byte order
a3 a2 a1 a0                      # msg.c in network byte order
b7 b6 b5 b4 b3 b2 b1 b0          # msg.d in network byte order
03 00 00 00                      # length of message.e, in network byte order
c7 c6 c5 c4 c3 c2 c1 c0          # msg.e[0] in network byte order
d7 d6 d5 d4 d3 d2 d1 d0          # msg.e[1] in network byte order
e7 e6 e5 e4 e3 e2 e1 e0          # msg.e[2] in network byte order
00                               # PayloadVariant::Foo type ID
bb aa                            # msg.payload.aa, where msg.payload is PayloadVariant::Foo(ExampleMessagePayload)
00 01 02 03 04 05 06 07 08 09    # msg.payload.bytes, where msg.payload is PayloadVariant::Foo(ExampleMessagePayload)
02 00 00 00                      # length of msg.payload_list, in network byte order
00                               # PayloadVariant::Foo type ID
dd cc                            # msg.payload_list[0].aa, where msg.payload_list[0] is a PayloadVariant::Foo(ExampleMessagePayload)
0a 0b 0c 0d 0e 0f 10 11 12 13    # msg.payload_list[0].bytes, where msg.payload_list[0] is a PayloadVariant::Foo(ExampleMessagePayload)
01                               # PayloadVariant::Bar type ID
33 22 11 00                      # msg.payload_list[1].0, where msg.payload_list[1] is a PayloadVariant::Bar(u32)
```

### Byte Buffer Types

THe following byte buffers are used within Stacks peer messsages:

```
pub struct MessageSignature([u8; 80]);
```

This is a fixed-length container for storing a cryptographic signature.
Not all bytes will be used, since signatures may have a variable length.

```
pub struct PeerAddress([u8; 16]);
```

This is a fixed-length container for an IPv4 or an IPv6 address.

```
pub struct Txid([u8; 32]);
```

This is a container for a transaction ID.  Transaction IDs are 32-byte
cryptographic hashes.

```
pub struct BurnchainHeaderHash([u8; 32]);
```

This is a container for the hash of a burn chain block header, encoded as a
32-byte cryptographic hash.

```
pub struct BlockHeaderHash([u8; 32]);
```

This is a container for the hash of a Stacks block or a Stacks microblock header
hash, encoded as a 32-byte cryptographic hash.

```
pub struct Secp256k1PublicKey([u8; 33]);
```

This is a compressed secp256k1 public key, as used in Bitcoin and other
cryptocurrencies.

```
pub struct DoubleSha256([u8; 32]);
```

This is a SHA256 hash applied twice to some data.

### Common Data Structures

This section details common data structures used in multiple messages.

**Neighbor Address**

The network address of a Stacks peer is encoded as follows:

```
pub struct NeighborAddress {
    /// The IPv4 or IPv6 address of this peer
    pub addrbytes: PeerAddress,

    /// The port this peer listens on
    pub port: u16,

    /// The RIPEMD160-SHA256 hash of the node's public key.
    /// If this structure is used to advertise knowledge of another peer,
    /// then this field _may_ be used as a hint to tell the receiver which
    /// public key to expect when it establishes a connection.
    pub public_key_hash: Hash160
}
```

**Relay Data**

Messages in the network preserve the order of peers that send them.  This
information is encoded as follows:

```
pub struct RelayData {
    /// The peer that relayed a message
    pub peer: NeighborAddress,

    /// The sequence number of that message (see the Preamble structure below)
    pub seq: u32,

    /// The peer's original signature over the message, including the relay
    /// metadata.
    pub signature: MessageSignature
}
```

### Messages

All Stacks messages have three components:

* A fixed-length **preamble** which describes some metadata about the peer's view of the
  network.

* A variable-length but bound-sized **relayer** vector which describes the order of peers that
  relayed a message.

* A variable-length **payload**, which encodes a specific peer message as a
  typed container.

All Stacks messages are represented as:

```
pub struct StacksMessage {
    pub preamble: Preamble,
    pub relayers: Vec<RelayData>,
    pub payload: StacksMessageType
}
```

The preamble has the following fields.  Descriptions of each field are provided
in-line.

```
pub struct Preamble {
    /// A 4-byte scalar to encode the semantic version of this software.
    /// The only valid value is 0x15000000 (i.e. version 21.0.0.0).
    pub peer_version: u32,

    /// A 4-byte scalar to encode which network this peer belongs to.
    /// Valid values are:
    ///   0x15000000 -- this is "mainnet"
    ///   0x15000001 -- this is "testnet"
    pub network_id: u32,

    /// A 4-byte scalar to encode the message sequence number.  A peer will
    /// maintain a sequence number for each neighbor it talks to, and will
    /// increment it each time it sends a new message (wrapping around if
    /// necessary).
    pub seq: u32,

    /// This is the height of the last burn chain block this peer processed.
    /// If the peer is all caught up, this is the height of the burn chain tip.
    pub block_height: u64,

    /// This is the consensus hash calculated at the block_height above.
    /// The consensus hash identifies the _fork set_ this peer belongs to, and
    /// is calculated as a digest over all burn chain transactions it has
    /// processed.
    pub consensus_hash: ConsensusHash,

    /// This is the height of the last stable block height -- i.e. the largest
    /// block height at which a block can be considered stable in the burn
    /// chain history.  In Bitcoin, this is at least 7 blocks behind block_height.
    pub stable_block_height: u64,

    /// This is the height of the last stable consensus hash -- the consensus
    /// hash calculated for the stable_block_height above.
    pub stable_consensus_hash: ConsensusHash,

    /// This is a signature over the entire message (preamble and payload).
    /// When generating this value, the signature bytes below must all be 0's.
    pub signature: MessageSignature;

    /// This is the length of the message payload.
    pub payload_len: u32;
}
```

A payload is a typed container, and may be any of the following enumerated
types:

```
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
    Nack(NackData)
}
```

### Payloads

**Handshake**

Type identifier: 0

Structure:

```
pub struct HandshakeData {
    /// Address of the peer sending the handshake
    pub addrbytes: PeerAddress,
    pub port: u16,

    /// Bit field of services this peer offers.
    /// Supported bits:
    /// -- SERVICE_RELAY = 0x0001 // must be set if the node relays messages
    pub services: u16,

    /// This peer's public key
    pub node_public_key: Secp256k1PublicKey,

    /// Burn chain block height at which this key will expire
    pub expire_block_height: u64
}
```

**HandshakeAccept**

Type identifier: 1

Structure:

```
pub struct HandshakeAcceptData {
    /// Maximum number of seconds the recipient peer expects this peer
    /// to wait between sending messages before the recipient will declare
    /// this peer as dead.
    pub heartbeat_interval: u32,

    /// The recipient peer's public key.
    pub node_public_key: Secp256k1PublicKey,
}
```

**HandshakeReject**

Type identifier: 2

Structure: [empty]

**GetNeighbors**

Type identifier: 3

Structure: [empty]

**Neighbors**

Type identifier: 4

Structure:

```
pub struct NeighborsData {
    /// List of neighbor addresses and public key hints.
    /// This vector will be at most 128 elements long.
    pub neighbors: Vec<NeighborAddress>
}
```

**GetBlocksInv**

Type identifier: 5

Structure:

```
pub struct GetBlocksData {
    /// Start height over which to query for blocks (inclusive)
    pub burn_height_start: u64,

    /// The hash of the burn chain header at the start height above.
    pub burn_header_hash_start: BurnchainHeaderHash,

    /// End height over which to query for blocks (exclusive)
    pub burn_height_end: u64,

    /// The hash of the burn chain header at the end height above.
    pub burn_header_hash_end: BurnchainHeaderHash
}
```

**BlocksInv**

Type identifier: 6

Structure:

```
pub struct BlocksInvData {
    /// Number of bits represented in the bit vector below.
    pub bitlen: u32,

    /// A bit vector of which blocks this peer has.  bitvec[i]
    /// represents the availability of the next 8*i blocks, where
    /// bitvec[i] & 0x01 represents the availability of the (8*i)th block, and
    /// bitvec[i] & 0x80 represents the availability of the (8*i+7)th block.
    /// Each bit corresponds to a sortition on the burn chain, and will be set
    /// if this peer has the winning block data
    pub bitvec: Vec<u8>,

    /// A list of microblocks this peer has data for.
    pub microblocks_inventory: Vec<MicroblocksInvData>
}

pub struct MicroblocksInvData {
    /// The offset of the bit in the BlocksInvData bitvec to which this
    /// this item corresponds.  i.e. this structure corresponds to bit
    /// bitvec[bit_index / 8] & (1 << (bit_index % 8))
    pub bit_index: u32,

    /// Whether or not the complete set of microblocks is available.
    pub complete: u8,

    /// The root of a Merkle tree composed of the sequence of microblocks'
    /// header hashes appended to this Stacks block.
    pub merkle_root: DoubleSha256;
}
```

**GetBlocks**

Type identifier: 7

Structure: Same as **GetBlocksInv**

**Blocks**

Type identifier: 8

Structure:

```
pub struct BlocksData {
    /// The list of Stacks blocks requested.  At most 32MB of data will
    /// be sent with this message.  The peer requesting the blocks will
    /// need to send successive GetBlocksData messages.
    pub blocks: Vec<StacksBlock>
}

pub struct StacksBlock {
   /// Omitted for a future SIP
}
```

**GetMicroblocks**

Type identifier: 9

Structure:

```
pub struct GetMicroblocksData {
    /// The burn chain block height at which the microblocks' on-chain parent is
    /// anchored.
    pub burn_header_height: u64,

    /// The hash of the burn chain block at the given height.
    pub burn_header_hash: BurnchainHeaderHash,

    /// The hash of the on-chain Stacks block whose parent is the
    /// last microblock in a chain of microblocks in-between itself
    /// and the previous on-chain Stacks block.
    pub block_header_hash: BlockHeaderHash,

    /// The hash of the microblock header to request
    pub microblock_header_hash: BlockHeaderHash
}
```

**Microblocks**

Type identifier: 10

Structure:

```
pub struct MicroblocksData {
    /// A contiguous sequence of microblocks.
    /// The _last_ item in this list has a header whose hash is equal to
    /// the requesting GetMicroblocksData's microblock_header_hash.
    /// At least one microblock must be present.  Over successive requests,
    /// the _first_ item of one of these messages will have a parent block
    /// hash that matches the on-chain block just before the on-chain block
    /// to which this microblock was appended.
    pub microblocks: Vec<StacksMicroblock>
}

pub struct StacksMicroblock {
   /// Omitted for a future SIP
}
```

**Transaction**

Type identifier: 11

Structure:

```
pub struct StacksTransaction {
   /// Omitted for a future SIP
}
```

**Nack**

Type identifier: 12

Structure:

```
pub struct NackData {
   /// Numeric error code to describe what went wrong
   pub error_code: u32
}
```

## Protocol Description

This section describes the algorithms that make up the Stacks peer-to-peer
network.  In these descriptions, there is a distinct **sender peer** and a
distinct **receiver peer**.

### Creating a Message

All messages start with a `Preamble`.  This allows peers to identify other peers
who (1) have an up-to-date view of the underlying burn chain, and (2) are part
of the same fork set.  In addition, the `Preamble` allows peers to authenticate
incoming messages and verify that they are not stale.

All messages are signed with the node's session private key using ECDSA on the
secp256k1 curve.  To sign a `StacksMessage`, a peer uses the following algorithm:

1. Serialize the `payload` to a byte string.
2. Set the `payload_len` field to the length of the `payload` byte string
3. Set the `seq` field in the `preamble` to be the number of messages sent to
   this peer so far.
4. Set the `preamble.signature` field to all 0's
5. Serialize the `premable` to a byte string.
6. Calculate the SHA256 over the `preamble` and `payload` byte strings
7. Calculate the (variable-length) secp256k1 signature from the SHA256
8. Encode the secp256k1 signature as a DER byte string
9. Copy the DER-encoded signature into `preamble.signature` as follows:
   a. Set `preamble.signature[0]` to the number of bytes in the DER-encoded string
   b. Copy the DER-encoded bytes into the `preamble.signature[1..80]` slice

### Receiving a Message

Because all messages start with a fixed-length `Preamble`, a peer receives a
message by first receiving the `Preamble`'s bytes and decoding it.  If the bytes
decode successfully, the peer _then_ receives the serialized payload, using the
`payload_len` field in the `Preamble` to determine how much data to read.  To
avoid memory exhaustion, **the payload may not be more than 32 megabytes**.

Once the preamble and payload message bytes are loaded, the receiver peer
verifies the message as follows:

1. Calculate the SHA256 hash over the serialized `preamble` and the payload
   bytes
2. Extract the DER-encoded signature from `preamble.signature`
3. Verify the signature against the sender peer's public key.
4. Verify that the `seq` field of the payload is greater than any
   previously-seen `seq` value for this peer.
5. Parse the payload typed container bytes into a `Payload`

### Error Handling

If anything goes wrong when communicating with a peer, the receiver may reply
with a `Nack` message with an appropriate error code.  Depending on the error,
the sender should try again, close the socket and re-establish the connection, or
drop the peer from its neighbor set altogether.  In particular, if a peer
receives an _invalid_ message from a sender, the peer should blacklist the remote
peer for a time.

Different aspects of the protocols will reply with different error codes to
convey exactly what went wrong.  However, in all cases, if the preamble is
well-formed but identifies a different network ID, a version field
with a different major version than the local peer, or different stable
consensus hash values, then both the sender and receiver peers should blacklist each other.

Because peers process the burn chain up to its chain tip, it is possible for
peers to temporarily be on different fork sets (i.e. they will have different
consensus hashes for the given chain tip, but will have the same values for
the locally-calculated consensus hashes at each other's `stable_block_height`'s).
If a peer detects this, then it should reply with a `Nack` indicating that they have different views of the
burn chain tip.  In this case, both peers should take it as a hint to first check
that their view of the burn chain is consistent (if they have not done so
recently), and the sender peer should try the request again.  If the sender
peer detects that its view of the burn chain is unchanged, then it
should execute a randomized exponential back-off when re-trying the request,
checking its view of the burn chain before each subsequent attempt.

Peers are expected to be both parsimonious and expedient in their communication.
If a remote peer sends too many valid messages too quickly, the peer
may throttle or blacklist the remote peer.  If a remote peer
is sending data too slowly, the recipient may terminate the connection and
optionally blacklist the remote peer.

### Connecting to a Peer

Connecting to a peer is done in a single round as follows:

1.  The sender peer creates a `Handshake` message with its address, services,
    and public key and sends it to the receiver.
2.  The receiver replies with a `HandshakeAccept` with its public key and
    services.

On success, both sender and receiver add each other to their frontier neighbor
sets.

If the receiver is unable to process the `Handshake`, the receiver should
reply with a `HandshakeReject` and temporarily blacklist the sender for a time.
Different implementations may have different considerations for what constitutes
an invalid `Handshake` request.  A `HandshakeReject` response should be used
only to indicate that the sender peer will be blacklisted.  If the `Handshake`
request cannot be processed for a _recoverable_ reason, then the receiver should
reply with a `Nack` with the appropriate error code to tell the sender to try
again.

### Exchanging Neighbors

Peers exchange knowledge about their neighbors as follows:

1. The sender peer creates a `GetNeighbors` message and sends it to the
   receiver.
2. The receiver chooses up to 128 neighbors it knows about and replies to the
   sender with them as a `Neighbors` message.  It provides the hashes of their session public keys (if
known) as a hint to the sender, which the sender may use to further
authenticate future neighbors (but this is optional).

On success, the sender peer adds zero or more of the replied peer addresses to
its frontier set.  The receiver does nothing.

If the sender receives an invalid `Neighbors` reply with more than 128
addresses, the sender should blacklist the receiver.

The sender is under no obligation to trust the public key hashes in the
`Neighbors` request.  However, if the sender trusts the receiver, then they can
be used as hints on the expected public keys if the sender subsequently
attempts to connect with these neighbors.  Deciding which nodes to trust
with replying true neighbor information is a peer-specific configuration option.

The receiver may reply with a `Nack` if it does not wish to divulge its
neighbors.  In such case, the sender should not ask this receiver for neighbors
again for a time.

### Requesting Blocks

Peers exchange blocks in a 2-round protocol:  the sender first queries the
receiver for the blocks it has, and then queries for ranges of blocks.

1.  The sender creates a `GetBlocksInv` message for a range of blocks it wants,
    and sends it to the receiver.
2.  If the receiver has processed the range of blocks represented by the `GetBlocksInv` 
    block range, then the receiver creates a `BlocksInv` message and replies
with it.  The receiver's inventory bit vector may be _shorter_ than the
requested range if it won't fit into a single message.  If so, the sender should
repeat step (1) to fetch the rest of the inventory until it has a full list of
what blocks the receiver possesses.
3. Once the sender knows which blocks the receiver possesses, the sender sends a
   `GetBlocksData` message to fetch a range of blocks.
4. On receipt of the `GetBlocksData` message, the receiver replies with a
   _contiguous_ range of blocks in a `BlocksData` reply.  If the receiver is
unable to send all blocks requested in one message. the receiver replies with as
many blocks as possible starting from the `GetBlocksData` payload's
`burn_height_start` / `burn_header_hash_start` locator.  In such case,
the sender repeats step (3) with a more recent `burn_height_start` /
`burn_header_hash_start` locator to keep requesting the blocks it wants.

On success, the sender receives the block data between two points in time on the
burn chain, as identified by a (height, header hash) pair.  In addition, for
each Stacks block received, the sender will obtain the hash calculated from the
root of a Merkle tree generated from all of a Stacks block's associated
microblocks.  This is used to subsequently request microblocks "in between" two
Stacks blocks, and determine that they are all present.

The receiver peer may reply with a `BlocksInv` or a `BlocksData` with as few
block inventory bits or block contents as it wants, but it must reply with at
least one inventory bit or at least one block.  If the receiver does not do so,
the sender should terminate the connection to the receiver and refrain from
contacting it for a time.

A receiver should reply with a Stacks block if it has it, even if it does not
have its parent block or is still missing some of its associated microblocks.
If it is missing some of its microblocks, the `complete` field will be 0 in the
microblocks inventory vector for the associated block.  Nevertheless, the
receiver will set the `merkle_root` field in the `MicroblocksInvData` structure
to be the hash of a Merkle tree composed of all Stacks microblock headers the
receiver has for this on-chain Stacks block. 

If the receiver cannot fulfill the request because it does not have the block
data, or has not processed the burn chain to the height requested by the sender,
then it should reply with a `Nack` message indicating as such.  If the sender
keeps asking for block data the receiver does not have, the receiver may
terminate the connection and blacklist the sender for a time.

### Requesting Microblocks

Microblocks are appended to Stacks blocks by block leaders (see SIP 001), and a
Stacks block may list a microblock as its block parent.  A peer will need to
fetch all microblocks "in between" two consecutive on-chain Stacks blocks in order to
provide the complete chain history between them.  A peer can tell whether or not
the set of microblocks between to consecutive on-chain blocks and microblocks is
complete by confirming that each microblock contains the hash of its immediate 
ancestor microblock, or the earlier on-chain block.  The microblocks in-between
two on-chain blocks must form a linear hash chain --- if two microblocks share
the same ancestor, both will be rejected.

A sender can ask for microblocks once it knows the hash of the last microblock's
header in a chain of microblocks.  This hash is obtained from a valid
on-chain Stacks block -- an on-chain Stacks block contains pointers both to the
previous on-chain Stacks block and to the last microblock mined on top of it.

To ask for microblocks between two consecutive on-chain blocks, a sender and
receiver execute the following steps:

1. The sender creates and sends a `GetMicroblocksData` message with a pointer to the block
   containing the ancestor of all the microblocks in the sequence, as well as
the earliest known microblock header hash in the sequence.  This is initially
obtained from the on-chain Stacks block whose ancestor is the last microblock.
2. The receiver replies with a `MicroblocksData` message with a vector of
   microblocks.  The last microblock in the vector must have a header whose hash
is equal to the sender's microblock header hash.

A sender and receiver peer iteratively execute steps 1 and 2 until the sender
has a copy of all microblocks in between two consecutive on-chain Stacks blocks.
The receiver replies with as many consecutive microblocks as it wants, but it
must reply at least one block in order for the sender to consider the
conversation successful.

If the receiver does not have any of the requested microblocks, it replies with a `Nack`
indicating as such.  The sender may try again later, such as with an exponential
back-off.

If the receiver replies with non-contiguous microblocks, the sender terminates
the connection and blacklists the receiver.

### Forwarding Data

Chain data may be forwarded to other peers without requesting them.  In such
case, a peer receives an unsolicited and un-asked-for `BlocksData`, `MicroblocksData`,
or `Transaction` message.

If the data has not been seen before by the peer, and the data is valid, then the peer
forwards it to a subset of its neighbors.  If it has seen the data before, it does not forward
it.  The process for determining whether or not a block or transaction is valid
will be discussed in a future SIP.  However, at a high level, the following
policies hold:

* A `StacksBlock` can only be valid if it corresponds to block commit
  transaction on the burn chain that won sortition.  A peer may cache a
`StacksBlock` if it determines that it has not yet processed the sortition that
makes it valid, but in such cases, the peer will _not_ relay the data.
* A `StacksMicroblock` can only be valid if it corresponds to a valid
  `StacksBlock` or a previously-accepted `StacksMicroblock`.  A peer may cache a
`StacksMicroblock` if it determines that a yet-to-arrive `StacksBlock` or
`StacksMicroblock` could make it valid in the near, but in such cases, the peer will _not_
relay the data.
* A `Transaction` can only be valid if it encodes a legal state transition on
  top of a Stacks blockchain tip.  A peer will _neither_ cache _nor_ relay a
`Transaction` message if it cannot determine that it is valid.

**Mapping the Peer Network**

When relaying data, the relaying peer must re-sign the message preamble and update its
sequence number to match each recipient peer's expectations on what the signature 
and message sequence will be.  In addition, the relaying peer appends the
upstream peer's message signature and previous sequence number in the
message's relayer vector.  In doing so, the recipient peers learn about the
_path_ that a message took through the peer network.  This serves the following
purposes:

* It helps a peer discover possible "choke points" in the network -- observed
  as the same few peers relaying most pmessages.
* It helps a peer detect network disruptions (in particular, BGP prefix hijacks) --
observed as a sets of peers with the same network prefix suddenly not relaying
messages.
* It helps a peer detect network churn (e.g. node outages, BGP updates) -- observed as
  frequently-seen paths no longer being used, or being replaced by other paths.
* It helps a peer discover more efficient routing paths than it would have
  through a naive store-and-forward relay algorithm.
* It helps a peer discover the "jurisdictional path" its messages could travel through, 
which helps a peer route around hostile networks that would delay, block, or
track the messages.

To avoid making itself into a target for network adversaries to harass,
a peer that originates a `BlocksData`, `MicroblocksData`, or `Transaction`
message should _not_ include itself in the `relayers` vector.  This is done to
protect the privacy of the originating peer, since (1) network attackers seeking to
disrupt the chain could do so by attacking block and microblock originators, and
(2) network attackers seeking to go after Stacks users could do so if they knew
or controlled the IP address of the victim's peer.  The fact that network
adversaries can be expected to harass message originators also serves to
discourage relaying peers from stripping the `relayers` vector from messsages,
lest they become the target of an attack.

A peer must include itself in the `relayers` vector when it forwards a message.
If it does not do so, a correct downstream peer can detect this by checking that
the upstream peer inserted its previously-announced address (i.e. the IP
address, port, and public key it sent in its `HandshakeData`).  If a relaying
peer does not update the `relayers` vector correctly, a downstream peer should
close the connection and blacklist the peer for a time.  It is important that
the `relayers` vector remains complete in order to detect and resist routing
disruptions in the Internet.

Nevertheless, not all peers are obligated to relay Stacks data.  If a peer does
not intend to relay messages, it _must_ clear the `SERVICE_RELAY` bit in its
`services` field when it executes a handshake with neighbor peer.  This way, the
neighbor will not expect any block, microblock, or transaction data from it.

### Choosing Neighbors

The Stacks peer network is designed to implement a K-regular random graph
topology, where _any_ peer may be chosen as a peer's neighbor.  The network is
a reachability network, anad is designed to be "maximally difficult" for a
network adversary to partition.  A random graph topology is suitable for this,
since the possibility that any peer may be a neighbor means that the only way to
cut off a peer from the network is to ensure it never discovers another honest
peer.

Peers maintain two views of the network:

* The **frontier** -- the set of peers that have either sent a message to this
  peer or have responded to a request in the past _L_ days (where _L_ is the
amount of time for which a peer may remain in the frontier set before being
considered for eviction).  The size of the frontier is significantly larger than
K.  Peer records in the frontier set may expire and may be stale, but are only
evicted when the space is needed.

* The **neighbor set** -- the set of K peers that the peer will announce as its
  neighbors when asked.  The neighbor set is a randomized subset of the frontier.

**Discovering Other Peers**

To construct a K-regular network topology, peers execute a Metropolis-Hastings
random graph walk with delayed acceptance [1] to decide which peers belong to
their neighbor set and to grow their frontiers.  A peer keeps track of which
peers are neighbors of which other peers, and in doing so, is able to calculate
the in-degree and out-degree of each peer in the neighbor set.  This is used to
calculate the probability of walking from one peer to another.

A peer keeps its neighbor set limited to K neighbors by evicting the
least-recently-visited node while walking through the neighbors' neighbors.  It
does not forget the evicted neighbor; it merely stops reporting it as a neighbor
when responding to a `GetNeighbors` query.

A peer adds nodes to its frontier by discovering them through this random graph walk, through
`Handshake` requests, and through the `relayers` vectors in the messages it
receives.  A peer is first added to the frontier set, and if it is fresh (or its
information can be refreshed), it may be walked to by the graph walk algorithm.
The graph walk algorithm will attempt to refresh a stale peer's data before
walking to it.

A peer remembers the network address and the
RIPEMD160-SHA256 hash of the public key given in the discovered `NeighborAddress` structure,
and uses the `NeighborAddress` data to later determine the legitimacy of the
discovered neighbor.  A remote peer in the frontier set is _not_
treated as a neighbor until the peer has had a chance to talk to it directly and
obtained its public key.  The RIPEMD160-SHA256 hash is used as a hint for
authenticating nodes discovered through the `relayer` vector in a message, and
for estimating a remote peer's in-degree and out-degree.

When the peer receives a `Neighbors` response while walking the graph, some of
the nodes will be in the peer's neighbor set already, some will only be
present in the frontier set (and may be stale), and some will be completely new.
For the remote peers' neighbors who are _not_ in the neighbor set already and
are either completely new or are stale, the peer executes 
a handshake with each of them to obtain or refresh its
knowledge of their public keys.  If a remote peer neighbor responds, its public
key is updated, its address and public key are added to the frontier set,
and the graph walk algorithm will consider walking to it.  If the remote
peer neighbor's public key hashes to the RIPEMD160-SHA256 key hash given by the
remote peer, then the remote peer's out-degree count is incremented (i.e. this
is a "legitimate" neighbor).  The in-degree of the remote peer neighbor is
incremented if the peer did not already know that this remote peer neighbor
listed the remote peer as its neighbor.  That is, if A is asking B for its
neighbors, and C is a neighbor of B, then A's in-degree count for C will be
incremented only if A learned that C was B's neighbor.

When a peer sees a relay peer in the `relayers` vector that is either not in its
frontier set or has an expired frontier record, the peer will attempt to
`Handshake` with it.  If the peer (a) responds with a `HandshakeAccept`, and (b)
the public key hashes to the expected public key hash from the `relayers` entry,
then the remote peer is both added to the frontier and its public key is
updated (i.e. the remote peer will be fresh).
This newly-added peer may be walked to from the neighbor set.  If on
the other hand the public key does _not_ match the public key hash in the
`relayers` vector, then the peer's address is stored to the frontier set and its
public key is marked as expired (i.e. the peer in the `relayers` list is marked
as stale in the frontier set).  The graph walk may eventually walk to this
node sometime in the future, but it is not treated as a candidate for the neighbor set
at this time.

**Promoting Route Diversity**

The neighbor selection algorithm attempts to select neighbors from a diverse set
of autonomous systems (ASs) in different jurisdictions.  This is important for
ensuring that a peer remains connected in the face of inter-AS partitions, which
would (from the peer's perspective) cause many nodes to suddenly go offline.
Such phenomena can occur as a result of BGP prefix hijacking, which has been
successfully deployed to attack existing cryptocurrencies.

Because messages include an authenticated network path, peers can infer over the
course of many peer messages which remote peers forward messages from other
peers.  A peer will build up a set of frequently-seen network path segments, and
measure how often future messages continue to pass through them.  From this, a
peer can infer which ASs their messages pass through by looking up the
autonomous system number (ASN) from the remote peer's IP address prefix.  Using this
information, the peer can add or remove neighbors to its neighbor set as a
function of how many distinct ASs are represented in the _path_ that would be
taken by a message.

This is realized by tweaking the Metropolis-Hastings graph walk algorithm.  A
peer weights the probability of walking to a neighbor by _also_ considering how many
ASs are reachable from it as part of calculating its in-degree and out-degree.
That is, the number of ASs reachable from a neighbor act as edge weights that
improve its chances of remaining in the neighbor set -- a neighbor's
out-degree/in-degree ratio is multiplied by the number of ASs it can reach, and
divided by the total number of ASs known across the peer's neighbor set.  As
such, all other things being equal, a peer will tend to add neighbors that
can reach many ASs, and will tend to drop peers that reach few ASs.

The authenticated paths in the `relayers` vector also serves to help a peer
identify network "choke points."  These are peers that are included in many paths,
such that if they went offline, a large number of paths would be broken.
To ensure that the peer does not end up relying on a few choke points for
connectivity, the graph walk algorithm will reduce the chance that a choke point
will remain in the neighbor set.  It does so by calculating the expected number of paths
that should pass through a given peer if the peer graph were truly random (call
this `P_E`), and calculating the number of paths that actually pass through the
peer (call this `P_N`).  Then the probability that the graph walk algorithm will
walk to this peer will be multiplied by `P_E / max(P_E, P_N)`.  This lowers the
probability that a choke point will remain in the neighbor set.

A full empirical evaluation on the effectiveness of this strategy at encouraging
route diversity will be done before this SIP is accepted.

## Reference Implementation

Implemented in Rust.

[1] See https://arxiv.org/abs/1204.4140 for details on the MHRWDA algorithm.
