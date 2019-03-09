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
buffers, vectors, and type containers.  Unlike a vector, there is no length
field for a typed container -- the parser will begin consuming the container's
items immediately following the 1-byte type identifier.

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
90 91                            # msg.b in network byte order
a0 a1 a2 a3                      # msg.c in network byte order
b0 b1 b2 b3 b4 b5 b6 b7          # msg.d in network byte order
00 00 00 03                      # length of message.e, in network byte order (note that vector lengths are always 4 bytes)
c0 c1 c2 c3 c4 c5 c6 c7          # msg.e[0] in network byte order
d0 d1 d2 d3 d4 d5 d6 d7          # msg.e[1] in network byte order
e0 e1 e2 e3 e4 e5 e6 e7          # msg.e[2] in network byte order
00                               # PayloadVariant::Foo type ID
aa bb                            # msg.payload.aa, where msg.payload is PayloadVariant::Foo(ExampleMessagePayload)
00 01 02 03 04 05 06 07 08 09    # msg.payload.bytes, where msg.payload is PayloadVariant::Foo(ExampleMessagePayload)
00 00 00 02                      # length of msg.payload_list, in network byte order
00                               # PayloadVariant::Foo type ID
cc dd                            # msg.payload_list[0].aa, where msg.payload_list[0] is a PayloadVariant::Foo(ExampleMessagePayload)
0a 0b 0c 0d 0e 0f 10 11 12 13    # msg.payload_list[0].bytes, where msg.payload_list[0] is a PayloadVariant::Foo(ExampleMessagePayload)
01                               # PayloadVariant::Bar type ID
00 11 22 33                      # msg.payload_list[1].0, where msg.payload_list[1] is a PayloadVariant::Bar(u32) in network byte order
```

### Byte Buffer Types

THe following byte buffers are used within Stacks peer messsages:

```
pub struct MessageSignature([u8; 80]);
```

This is a fixed-length container for storing a cryptographic signature.
Not all bytes will be used, since signatures may have a variable length.
Unused bytes are at the highest addresses (on the "right").  For example, 
if the encoded signature data is `0x12 0x34 0x56 0x78`, then the `MessageSignature`
would be represented as

```
12 34 56 78             # the actual data
00 00 00 00 ...         # padding
```

Any value can be used as padding.

Each signature scheme will have its own way of using these bytes.  The encoding
scheme for a secp256k1 signature is described below, since it is used to help
make neighbor selections:

1. Encode the secp256k1 signature as a DER-encoded byte string
2. Set `MessageSignature[0]` to be the length fo the DER-encoded string
3. Copy the DER-encoded string to `MessageSignature[1..79]`

Any high-address unused bytes beyond the length of the DER-encoded string
will be ignored.

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
    pub burn_block_height: u64,

    /// This is the consensus hash calculated at the burn_block_height above.
    /// The consensus hash identifies the _fork set_ this peer belongs to, and
    /// is calculated as a digest over all burn chain transactions it has
    /// processed.
    pub burn_consensus_hash: ConsensusHash,

    /// This is the height of the last stable block height -- i.e. the largest
    /// block height at which a block can be considered stable in the burn
    /// chain history.  In Bitcoin, this is at least 7 blocks behind block_height.
    pub stable_burn_block_height: u64,

    /// This is the height of the last stable consensus hash -- the consensus
    /// hash calculated for the stable_block_height above.
    pub stable_burn_consensus_hash: ConsensusHash,

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
    Nack(NackData),
    Ping
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
    /// -- SERVICE_RELAY = 0x0001 -- must be set if the node relays messages
    ///                              for other nodes.
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

Notes:

* Expected reply is a `BlocksInvData`.
* `burn_height_end` can't be more than `burn_height_start + 4096`
* A `BlocksInvData` reply may not cover the entire range if it cannot fit into
  the maximum message size, or if `burn_height_end` exceeds the burn chain
height.

**BlocksInv**

Type identifier: 6

Structure:

```
pub struct BlocksInvData {
    /// Number of bits represented in the bit vector below.
    /// Represents the number of blocks in this inventory.
    /// This will be at most burn_height_end - burn_height_start from the
    /// GetBlocksData, but it may be fewer if the message would be too big.
    pub bitlen: u16,

    /// A bit vector of which blocks this peer has.  bitvec[i]
    /// represents the availability of the next 8*i blocks, where
    /// bitvec[i] & 0x01 represents the availability of the (8*i)th block, and
    /// bitvec[i] & 0x80 represents the availability of the (8*i+7)th block.
    /// Each bit corresponds to a sortition on the burn chain, and will be set
    /// if this peer has the winning block data
    pub bitvec: Vec<u8>,

    /// A list of microblocks this peer has data for.
    /// Has length equal to bitlen, and entries are in order by block --
    /// the ith bit in bitvec corresponds to the ith entry in this vector.
    pub microblocks_inventory: Vec<MicroblocksInvData>
}

pub struct MicroblocksInvData {
    /// The sequence of microblock hashes.
    pub hashes: Vec<BlockHeaderHash>
}
```

Notes:

* `BlocksInvData.bitlen` will never exceed 4096
* `BlocksInvData.bitvec` will have length `ceil(BlocksInvData.bitlen / 8)`
* `MicroblocksInvData.hashes` will never have more than 4096 elements.

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

**Ping**

Type identifier: 13

Structure: [empty]

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

A sender should only attempt to `Handshake` with a receiver if it believes that
the receiver has either not seen the sender peer before, or if its knowledge of
teh sender's public key is expired.  This is important since it stops a network
attacker from flooding a peer's neighbor table with invalid entries.  If the
receiver receives an "early" `Handshake` from a sender -- i.e. the receiver's
knowledge of the sender is still fresh, the receiver should reply with a `Nack`
to indicate so.

When executing a handshake, a peer should _not_ include any other peers in the
`relayers` vector except for itself.  A receiver should `Nack` a `Handshake`
with a `relayers` vector with more than one entry.

### Checking a Peer's Liveness

A sender peer can check that a peer is still alive by sending it a `Ping`
message.  The receiver should reply with a `Pong` message, and include the same
data it would have included in a `HandshakeAccept` response.  Both the sender
and receiver peers would update their metrics for measuring each other's
resposniveness, but they do _not_ alter any information about each other's
public keys and expirations.

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

The Stacks peer network implements a flooding network for blocks and
transactions in order to ensure that all peers receive a full copy of the chain
state as it arrives on the network.  Chain data may be forwarded to other
peers without requesting them.  In such
case, a peer receives an unsolicited and un-asked-for `BlocksData`, `MicroblocksData`,
or `Transaction` message.  Per the `Handshake` documentation, note that a downstream 
peer will only accept a relayed message if the relayer had set the
`SERVICE_RELAY` bit in its handshake's `services` bitfield.

If the data has not been seen before by the peer, and the data is valid, then the peer
forwards it to a subset of its neighbors (excluding the one that sent the data). 
If it has seen the data before, it does not forward
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

### Choosing Neighbors

The core design principle of the Stacks peer network is to maximize the entropy
of the peer graph.  Doing so helps ensure that the network's connectivity
avoids depending too much on a small number of popular peers and network edges.
While this may slow down message propagation relative to more structured peer graphs,
the _lack of_ structure is the key to making the Stacks peer network
resilient.

This principle is realized through a randomized neighbor selection algorithm.
The neighbor selection algorithm is designed to be able to address the following
concerns:

* It helps a peer discover possible "choke points" in the network, and devise
  alternative paths around them.
* It helps a peer detect network disruptions (in particular, BGP prefix hijacks) --
observed as a sets of peers with the same network prefix suddenly not relaying
messages, or sets of paths through particular IP blocks no longer being taken.
* It helps a peer discover the "jurisdictional path" its messages could travel through, 
which helps a peer route around hostile networks that would delay, block, or
track the messages.

To achieve this, the Stacks peer network is structured as a K-regular random graph,
where _any_ peer may be chosen as a peer's neighbor.  The network forms
a _reachability_ network, with the intention of being "maximally difficult" for a
network adversary to disrupt by way of censoring individual nodes and network
hops.  A random graph topology is suitable for this,
since the possibility that any peer may be a neighbor means that the only way to
cut off a peer from the network is to ensure it never discovers another honest
peer.

To choose their neighbors in the peer graph, peers maintain two views of the network:

* The **frontier** -- the set of peers that have either sent a message to this
  peer or have responded to a request in the past _L_ days (where _L_ is the
amount of time for which a peer may remain in the frontier set before being
considered for eviction).  The size of the frontier is significantly larger than
K.  Peer records in the frontier set may expire and may be stale, but are only
evicted when the space is needed.  The **fresh frontier set** is the subset of
the frontier set whose information is assumed to be valid at the time of query.

* The **neighbor set** -- the set of K peers that the peer will announce as its
  neighbors when asked.  The neighbor set is a randomized subset of the frontier.
Unlike the frontier set, the peer continuously refreshes knowledge of the state
of the neighbor sets' blocks and transactions in order to form a transaction and
block relay network.

Using these views of the network, the peers execute a link-state routing
protocol whereby each peer determines each of its neighbors' neighbors,
and in doing so, builds up a partial view of the routing graph made up of
recently-visited nodes.  Peers execute a route recording protocol whereby each 
message is structured to record the _path_ it took
through the graph's nodes.  This enables a peer to determine how often other peers
in its frontier, as well as the network links between them, are responsible for
relaying messages.  This knowledge, in turn, is used to help the peer seek out
new neighbors and neighbor links to avoid depending on popular peers and 
links too heavily.

**Discovering Other Peers**

To construct a K-regular random graph topology, peers execute a Metropolis-Hastings
random graph walk with delayed acceptance (MHRWDA) [1] to decide which peers belong to
their neighbor set and to grow their frontiers.

A peer keeps track of which peers are neighbors of which other peers, and in
doing so, is able to calculate the in-degree and out-degree of each peer in
the neighbor set.  This is used to help calculate the probability of walking
from one peer to another.  A peer measures the in-degree of a remote peer
simply by counting up the number of distinct neighbors it has.  It measures
the out-degree of a remote peer by counting up how many other peers have
included it in their K-neighbor sets recently.  A peer is walked to with
probability that is around `out-degree / in-degree` (but see [1] for details --
the exact probability formula is omitted for brevity).

A peer keeps its neighbor set limited to K neighbors by evicting the
least-recently-visited node while walking through the neighbors' neighbors.  It
does not forget the evicted neighbor; it merely stops reporting it as a neighbor
when responding to a `GetNeighbors` query.

A peer keeps its neighbor set fresh by periodically re-handshaking with its K
neighbors.  It will measure the health of each neighbor by measuring how often
it responds to a query.  A peer will probabilistically evict a peer from its
neighbor set if its response rate drops too low, where the probability of
eviction is proportional both to the peer's perceived uptime and to the peer's
recent downtime.

**Curating a Frontier**

In addition to finding neighbors, a peer curates a frontier set to (1) maintain knowledge
of backup peers to contact in case a significant portion of their neighbors goes
offline, and (2) to make inferences about the global connectivity of the peer
graph.  A peer can't crawl each and every other peer in the
frontier set (this would be too expensive), but a peer can infer over time which
nodes and edges are likely to be online.  The set of peers thought to be online
is called the _fresh frontier set_.

The fresh frontier set is used to estimate the connectivity of the
peer network in terms of the _autonomous systems_ that host them.  All that a
peer needs to know about remote peers in the fresh frontier set is that they are
likely to be online; it does _not_ need to know their current public keys and
block inventories.  That said, a peer remembers the following information for
peers in its frontier:

* the time it was inserted into the frontier (`T-insert`)
* the time it was last successfully contacted (`T-contact`)
* the number of times it has been successfully contacted in the last 10 days (`C-success`)
* the number of times it has failed to respond in the last 10 days (`C-failure`)

A peer is considered to be in the fresh frontier set if the following are true:

* `T-contact` is less than 10 days ago.
* `C-success / (C-success + C-failure) >= 0.5`: the peer replied at least 50% of the time in the last 10 days if this peer contacted it.

The frontier set grows whenever new neighbors are discovered.  A neighbor
inserted deterministically into the frontier set by hashing its address with a
peer-specific secret and the values `0` through `8` in order to identify eight
slots into which its address can be inserted.  If any of the resulting slots are
empty, the peer is added to the frontier.

The frontier set is large, but not infinite.  As more peers are discovered, it
becomes possible that a newly-discovered peer cannot be inserted
determinstically.  This will become more likely than not to happen once the
frontier set has `8 * sqrt(F)` slots full, where `F` is the maximum size of
the frontier.  In such cases, a random existing peer in one of the slots is
chosen for possible eviction, but only if it is offline.  The peer will attempt
to ping or (if its data is expired) handshake with the existing peer
before evicting it, and if it responds, the
new node is discarded and no eviction takes place.

Insertion and deletion are deterministic (and in deletion's case, predicated on
a failure to ping) in order to prevent a malicious remote peer from filling up
the frontier set with junk.  The ping-then-evict test is in place also to
prevent peers with a longer uptime from being easily replaced by short-lived peers.

**Mapping the Peer Network**

The Stacks protocol includes a route recording mechanism for peers to probe network paths.
This is used to measure how frequently peers and connections are used in the peer
graph.  This information is encoded in the `relayers` vector in each message.

When relaying data, the relaying peer must re-sign the message preamble and update its
sequence number to match each recipient peer's expectations on what the signature 
and message sequence will be.  In addition, the relaying peer appends the
upstream peer's message signature and previous sequence number in the
message's `relayer` vector.  In doing so, the recipient peers learn about the
_path_ that a message took through the peer network.  This information will be
used over time to promote message route diversity (see below).

A peer that relays messages _must_ include itself at the end of the
`relayers` vector when it forwards a message.
If it does not do so, a correct downstream peer can detect this by checking that
the upstream peer inserted its previously-announced address (i.e. the IP
address, port, and public key it sent in its `HandshakeData`).  If a relaying
peer does not update the `relayers` vector correctly, a downstream peer should
close the connection and possibly throttle the peer (blacklisting should not
be used since this can happen for benign reasons -- for example, a node on a
laptop may change IP addresses between a suspend/resume cycle).  Nevertheless,
it is important that the `relayers` vector remains complete in order to detect and resist routing
disruptions in the Internet.

Not all peers are relaying peers -- only peers that set the `SERVICE_RELAY`
bit in their handshakes are required to relay messages and list themselves in the `relayers` vector.
Peers that do not do this may nevertheless _originate_ an unsolicited `BlocksData`,
`MicroblocksData`, or `Transaction` message.  However, its `relayers` vector _must_ be
empty.  This option is available to protect the privacy of the originating peer, since
(1) network attackers seeking to disrupt the chain could do
so by attacking block and microblock originators, and
(2) network attackers seeking to go after Stacks users could do so if they knew
or controlled the IP address of the victim's peer.  The fact that network
adversaries can be expected to harass originators who advertise their network
addresses serves to discourage relaying peers from stripping the
`relayers` vector from messsages, lest they become the target of an attack.

A peer may transition between being a relaying peer and a non-relaying peer by
closing a connection and re-establishing it with a new handshake.  A peer that
violates the protocol by advertising their `SERVICE_RELAY` bit and not
updating the `relayers` vector should be blacklisted by downstream
peers.

A peer must not forward messages with invalid `relayer` vectors.  At a minimum,
the peer should authenticate the upstream peer's signature on the last entry of
the `relayers` vector.  If the message is invalid, then the message must not be
forwarded (and the sender may be throttled).  In addition, 
a peer that receives a message from an upstream peer without the
 `SERVICE_RELAY` bit that includes a `relayers` vector _must not_ forward it.
A peer that receives a message that contains duplicate entries in the `relayers`
vector (or sees itself in the `relayers` vector) _must not_ forward the message
either, since the message has been passed in a cycle.

**Promoting Route Diversity**

Over time, the peer will measure the routes taken by messages to determine
whether or not the network is _implicitly_ structured -- that is, whether
or not network reachability has come to rely 
on substantially fewer nodes and edges than would be expected in a random peer
graph.  This is used to inform the graph walk algorithm and the
forwarding algorithm to select _against_ frequently-used nodes and edges, so
that alternative network paths will be maintained by the peer network.

The peer network employs two heuristics to prevent the network from becoming
implicitly structured:

* Considering the AS-degree:  the graph walk algorithm will consider a peer's
connectivity to different _autonomous systems_
(ASs) when considering adding it to the neighbor set.

* Relaying in rarest-AS-first order:  the relay algorithm will probabilistically
  rank its neighbors in order by how rare their AS is the fresh frontier set.

When calculating the probability that a peer will be visited, the graph walk
algorithm calculates an additional measure of the peer's degree in the peer graph:
the in-degree and out-degree of the ASs represented by its neighbors.  The graph walk
algorithm will visit a new node with probability proportional to
`(out-degree / in-degree) * (out-AS-degree / in-AS-degree)`.  In doing so,
responsive peers that have high out-degrees relative to in-degrees will be prioritized for
inclusion in the neighbor set.

To forward messages to as many different ASs as possible, the peer will
probabilistically prioritize neighbors to receive a forwarded message based on how _rare_
their AS is in the frontier set.  This forwarding heuristic is
meant to ensure that a message quickly reaches many different networks in the
Internet.

The rarest-AS-first heuristic is implemented as follows:

1. The peer examines the `relayers` vector and attempts to handshake with a 
   peer if it is not in the fresh frontier set.  Any peers that fail the handshake, or have
public keys that differ from the relayer entry's public key hash will be dropped
from consideration.  This lets the peer add nodes in as-of-yet-unreached ASs to its
frontier, and lets the peer build up the set `AuthAS` of autonomous systems
represented by the authenticated portions of the `relayers` vector.
2. The peer builds a table `N[AS]` that maps its fresh frontier set's ASs to the list of peers
   contained within.  `len(N[AS])` is the number of fresh frontier peers in `AS`.
3. The peer assigns each neighbor a probability of being selected to receive the
   message next.  The probability depends on whether or not the neighbor is in
   one of the ASs in `AuthAS`:  the probability is
   `1 - len(N[AS]) / K` if `AS` is not in `AuthAS`, 
   `1 - (len(N[AS]) + 1) / K` if `AS` is present in `AuthAS`.
4.  The peer selects a neighbor according to the distribution, forwards the message to it, and
    removes the neighbor from consideration for this message.  The peer repeats step 3 until all neighbors have
    been sent the message.

The probability distribution in step 3 ensures that ASs that are less
well-represented by this peer are more likely to receive the message next.  The
`relayers` vector serves to decrease the chance of a neighbor being selected if
it is in an AS that has already been visited.  Nevertheless, the probability
distribution helps ensure that as a message is relayed more and more times,
peers will become increasingly prone to sending the message to
neighbors in ASs that have not yet seen the message.

A full empirical evaluation on the effectiveness of these heuristics at encouraging
route diversity will be carried out before this SIP is accepted.

**Miner-Assisted Peer Discovery**

Stacks miners are already incentivized to maintain good connectivity with one
another and with the peer network in order to ensure that they work on the
canonical fork.  As such, a correct miner may include the root of a Merkle tree of a set
of "reputable" peers that are known by the miner to be well-connected.  Other
peers in the peer network would include these reputable nodes in their frontiers
by default.

A peer ultimately makes its own decisions on who its neighbors are, but by 
default, a peer selects a miner-recommended peer only if over 75% of the mining power recommends
the peer for a long-ish interval (on the order of weeks).  The 75% threshold
follows from selfish mining -- the Stacks blockchain prevents selfish mining as
long as at least 75% of the hash power is honest.  If over 75% of the mining
power recommends a peer, then the peer has been recommended through an honest
process and may be presumed "safe" to include in the frontier set.

A recommended peer would not be evicted from the frontier set unless it could
not be contacted, or unless overridden by a local configuration option.

## Reference Implementation

Implemented in Rust.  The neighbor set size K is set to 16.  The frontier set size
is set to hold 2^24 peers (with evictions becoming likely after insertions once
it has 32768 entries).

[1] See https://arxiv.org/abs/1204.4140 for details on the MHRWDA algorithm.
[2] https://stuff.mit.edu/people/medard/rls.pdf
