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
preferred to a structured graph (like a DHT) in order to maximize the number of next-hop
(neighbor) peers that a given peer will consider in its frontier.  When choosing neighbors, a peer
will prefer to maximize the number of _distinct_ autonomous systems represented
in its frontier in order to help keep as many networks on the Internet connected
to the Stacks peer network.

## Specification

The following subsections describe the data structures and protocols for the
Stacks peer network.  In particular, this document discusses _only_ the peer
network message structure and protocols.  It does _not_ document the structure
of Stacks transactions and blocks.  These structures are defined in SIP 005.

### Encoding Conventions

This section explains how this document will describe the Stacks messages, and
explains the conventions used to encode Stacks messages as a sequence of bytes.

All Stacks network messages are composed of _scalars_, _byte buffers_ of fixed
length, _vectors_ of variable length, and _typed containers_ of variable length.

A scalar is a number represented by 1, 2, 4, or 8 bytes, and is unsigned.
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
let msg = ExampleMessage {
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

The following byte buffers are used within Stacks peer messsages:

```
pub struct MessageSignature([u8; 65]);
```

This is a fixed-length container for storing a recoverable secp256k1
signature.  The first byte is the recovery code; the next 32 bytes are the `r`
parameter, and the last 32 bytes are the `s` parameter.  Because there are up to
two valid signature values for a secp256k1 curve, only the signature with the _lower_
value for `s` will be accepted.

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

```
pub struct Sha512Trunc256([u8; 32]);
```

This is a container for a SHA512/256 hash.

```
pub struct TrieHash([u8; 32]);
```

This is a container for a MARF merkle hash (see SIP-004).

```
pub struct UrlString(Vec<u8>);
```

This is a container for an ASCII string that encodes a URL.  It is encoded as
follows:
* A 1-byte length prefix
* The string's bytes, as-is.

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
}
```

### Messages

All Stacks messages have three components:

* A fixed-length **preamble** which describes some metadata about the peer's view of the
  network.

* A variable-length but bound-sized **relayers** vector which describes the order of peers that
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

    /// A 4-byte scalar to encode the message sequence number. A peer will
    /// maintain a sequence number for each neighbor it talks to, and will
    /// increment it each time it sends a new message (wrapping around if
    /// necessary).
    pub seq: u32,

    /// This is the height of the last burn chain block this peer processed.
    /// If the peer is all caught up, this is the height of the burn chain tip.
    pub burn_block_height: u64,

    /// This is the burn block hash calculated at the burn_block_height above.
    /// It uniquely identifies a burn chain block.
    pub burn_header_hash: BurnchainHeaderHash,

    /// This is the height of the last stable block height -- i.e. the largest
    /// block height at which a block can be considered stable in the burn
    /// chain history.  In Bitcoin, this is at least 7 blocks behind block_height.
    pub stable_burn_block_height: u64,

    /// This is the hash of the last stable block's header.
    pub stable_burn_header_hash: BurnchainHeaderHash,

    /// This is a pointer to additional data that follows the payload.
    /// This is a reserved field; for now, it should all be 0's.
    pub additional_data: u32,

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
    GetPoxInv(GetPoxInv),
    PoxInv(PoxInvData),
    BlocksAvailable(BlocksAvailableData),
    MicroblocksAvailable(MicroblocksAvailableData),
    Blocks(BlocksData),
    Microblocks(MicroblocksData),
    Transaction(StacksTransaction),
    Nack(NackData),
    Ping,
    Pong
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
    pub expire_block_height: u64,

    /// HTTP(S) URL to where this peer's block data can be fetched
    pub data_url: UrlString
}
```

**HandshakeAccept**

Type identifier: 1

Structure:

```
pub struct HandshakeAcceptData {
    /// The remote peer's handshake data
    pub handshake: HandshakeData,

    /// Maximum number of seconds the recipient peer expects this peer
    /// to wait between sending messages before the recipient will declare
    /// this peer as dead.
    pub heartbeat_interval: u32,
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
pub struct GetBlocksInv {
    /// The consensus hash at the start of the requested reward cycle block range
    pub consensus_hash: ConsensusHash, 
    /// The number of blocks after to this consensus hash, including the block
    /// that corresponds to this consensus hash.
    pub num_blocks: u16 
}
```

Notes:

* Expected reply is a `BlocksInv`.
* `consensus_hash` must correspond to a (burnchain) block at the start of a PoX reward cycle
* `num_blocks` cannot be more than the PoX reward cycle length (see SIP-007).

**BlocksInv**

Type identifier: 6

Structure:

```
pub struct BlocksInvData {
    /// Number of bits represented in the bit vector below.
    /// Represents the number of blocks in this inventory.
    pub bitlen: u16,

    /// A bit vector of which blocks this peer has.  bitvec[i]
    /// represents the availability of the next 8*i blocks, where
    /// bitvec[i] & 0x01 represents the availability of the (8*i)th block, and
    /// bitvec[i] & 0x80 represents the availability of the (8*i+7)th block.
    /// Each bit corresponds to a sortition on the burn chain, and will be set
    /// if this peer has the winning block data
    pub block_bitvec: Vec<u8>,

    /// A bit vector for which confirmed microblock streams this peer has.
    /// The ith bit represents the presence/absence of the ith confirmed
    /// microblock stream.  It is in 1-to-1 correspondance with block_bitvec.
    pub microblocks_bitvec: Vec<u8>
}
```

Notes:

* `BlocksInvData.bitlen` will never exceed 4096
* `BlocksInvData.block_bitvec` will have length `ceil(BlocksInvData.bitlen / 8)`
* `BlocksInvData.microblocks_bitvec` will have length `ceil(BlocksInvData.bitlen / 8)`

**GetPoxInv**

Type identifier: 7

Structure:

```
pub struct GetPoxInv {
    /// The consensus hash at the _beginning_ of the requested reward cycle range
    pub consensus_hash: ConsensusHash,
    /// The number of reward cycles to request (number of bits to expect)
    pub num_cycles: u16
}
```

Notes:

* Expected reply is a `PoxInv`
* `num_cycles` cannot be more than 4096

**PoxInv**

Type identifier: 8

Structure:

```
pub struct PoxInvData {
    /// Number of reward cycles encoded
    pub bitlen: u16,
    /// Bit vector representing the remote node's PoX vector.
    /// A bit will be `1` if the node is certain about the status of the 
    /// reward cycle's PoX anchor block (it either cannot exist, or the
    /// node has a copy), or `0` if the node is uncertain (i.e. it may exist
    /// but the node does not have a copy if it does).
    pub pox_bitvec: Vec<u8>
}

Notes:
* `bitlen` should be at most `num_cycles` from the corresponding `GetPoxInv`.

**BlocksAvailable**

Type identifier: 9

Structure:

```
pub struct BlocksAvailableData {
    /// List of blocks available
    pub available: Vec<(ConsensusHash, BurnchainHeaderHash)>,
}
```

Notes:

* Each entry in `available` corresponds to the availability of an anchored
  Stacks block from the sender.
* `BlocksAvailableData.available.len()` will never exceed 32.
* Each `ConsensusHash` in `BlocksAvailableData.available` must be the consensus
  hash calculated by the sender for the burn chain block identified by
`BurnchainHeaderHash`.

**MicroblocksAvailable**

Type identifier: 10

Structure:

```
// Same as BlocksAvailable
```

Notes:

* Each entry in `available` corresponds to the availability of a confirmed
  microblock stream from the sender.
* The same rules and limits apply to the `available` list as in
  `BlocksAvailable`.
   
**Blocks**

Type identifier: 11

Structure:

```
pub struct BlocksData {
    /// A list of blocks pushed, paired with the consensus hashes of the
    /// burnchain blocks that selected them
    pub blocks: Vec<(ConsensusHash, StacksBlock)>
}

pub struct StacksBlock {
   /// Omitted for brevity; see SIP 005
}
```

**Microblocks**

Type identifier: 12

Structure:

```
pub struct MicroblocksData {
    /// "Index" hash of the StacksBlock that produced these microblocks.
    /// This is the hash of both the consensus hash of the burn chain block
    /// operations that selected the StacksBlock, as well as the StacksBlock's
    /// hash itself.
    pub index_anchor_hash: StacksBlockId,
    /// A contiguous sequence of microblocks.
    pub microblocks: Vec<StacksMicroblock>
}

pub struct StacksMicroblock {
   /// Omited for brevity; see SIP 005
}
```

**Transaction**

Type identifier: 13

Structure:

```
pub struct StacksTransaction {
   /// Omitted for brevity; see SIP 005
}
```

**Nack**

Type identifier: 14

Structure:

```
pub struct NackData {
   /// Numeric error code to describe what went wrong
   pub error_code: u32
}
```

**Ping**

Type identifier: 15

Structure:

```
pub struct PingData {
   /// Random number
   nonce: u32
}
```

**Pong**

Type identifier: 16

Structure:

```
pub struct PongData {
   /// Random number
   nonce: u32
}
```

**NatPunchRequest**

Type identifier: 17

Structure:

```
/// a 4-byte nonce unique to this request
u32
```

**NatPunchReply**

Type identifier: 18

Structure:

```
pub struct NatPunchData {
   /// The public IP address, as reported by the remote peer
   pub addrbytes: PeerAddress,
   /// The public port
   pub port: u16,
   /// The nonce from the paired NatPunchRequest
   pub nonce: u32,
}
```

Notes:
* The `nonce` field in a `PongData` should match the `nonce` field sent by the
  corresponding `Ping`.


## Protocol Description

This section describes the algorithms that make up the Stacks peer-to-peer
network.  In these descriptions, there is a distinct **sender peer** and a
distinct **receiver peer**.

### Network Overview

The Stacks peer network has a dedicated _control plane_ and _data plane_.  They
listen on different ports, use different encodings, and fulfill different roles.

The control-plane is implemented via sending messages using the encoding
described above.  It is concerned with the following tasks:
* Identifying and connecting with other Stacks peer nodes
* Crawling the peer graph to discover a diverse set of neighbors
* Discovering peers' data-plane endpoints
* Synchronizing block and microblock inventories with other peers.

The data-plane is implemented via HTTP(S), and is concerned with both fetching
and relaying blocks, microblocks, and transactions.

Each Stacks node implements the control-plane protocol in order to help other
nodes discover where they can fetch blocks.  However, Stacks nodes do _not_ need
to implement the data plane.  They can instead offload some or all of this responsibility to
other Stacks nodes, Gaia hubs, and vanilla HTTP servers.  The reason for this is
to **preserve compatibility with existing Web infrastructure** like cloud
storage and CDNs for doing the "heavy lifting" for propagating the blockchain
state.

### Creating a Control-Plane Message

All control-plane messages start with a `Preamble`.  This allows peers to identify other peers
who (1) have an up-to-date view of the underlying burn chain, and (2) are part
of the same fork set.  In addition, the `Preamble` allows peers to authenticate
incoming messages and verify that they are not stale.

All control-plane messages are signed with the node's session private key using ECDSA on the
secp256k1 curve.  To sign a `StacksMessage`, a peer uses the following algorithm:

1. Serialize the `payload` to a byte string.
2. Set the `preamble.payload_len` field to the length of the `payload` byte string
3. Set the `preamble.seq` field to be the number of messages sent to
   this peer so far.
4. Set the `preamble.signature` field to all 0's
5. Serialize the `preamble` to a byte string.
6. Calculate the SHA512/256 over the `preamble` and `payload` byte strings
7. Calculate the recoverable secp256k1 signature from the SHA256

### Receiving a Control-Plane Message

Because all control-plane messages start with a fixed-length `Preamble`, a peer receives a
message by first receiving the `Preamble`'s bytes and decoding it.  If the bytes
decode successfully, the peer _then_ receives the serialized payload, using the
`payload_len` field in the `Preamble` to determine how much data to read.  To
avoid memory exhaustion, **the payload may not be more than 32 megabytes**.

Once the preamble and payload message bytes are loaded, the receiver peer
verifies the message as follows:

1. Calculate the SHA256 hash over the serialized `preamble` and the payload
   bytes
2. Extract the recoverable signature from `preamble.signature`
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
peer for a time (i.e. ignore any future messages from it).

Different aspects of the control-plane protocol will reply with different error codes to
convey exactly what went wrong.  However, in all cases, if the preamble is
well-formed but identifies a different network ID, a version field
with a different major version than the local peer, or different stable
burn header hash values, then both the sender and receiver peers should blacklist each other.

Because peers process the burn chain up to its chain tip, it is possible for
peers to temporarily be on different fork sets (i.e. they will have different
burn header hashes for the given chain tip, but will have the same values for
the stable burn header hashes at each other's `stable_block_height`'s).
In this case, both peers should take it as a hint to first check
that their view of the burn chain is consistent (if they have not done so
recently).  They may otherwise process and react to each other's messages
without penalty.

Peers are expected to be both parsimonious and expedient in their communication.
If a remote peer sends too many valid messages too quickly, the peer
may throttle or blacklist the remote peer.  If a remote peer
is sending data too slowly, the recipient may terminate the connection in order
to free resources for serving more-active peers.

### Connecting to a Peer's Control Plane

Connecting to a peer's control-plane is done in a single round as follows:

1.  The sender peer creates a `Handshake` message with its address, services,
    and public key and sends it to the receiver.
2.  The receiver replies with a `HandshakeAccept` with its public key and
    services.

On success, the sender adds the receiver to its frontier set.  The receiver may
do so as well, but this is not required.

If the receiver is unable to process the `Handshake`, the receiver should
reply with a `HandshakeReject` and temporarily blacklist the sender for a time.
Different implementations may have different considerations for what constitutes
an invalid `Handshake` request.  A `HandshakeReject` response should be used
only to indicate that the sender peer will be blacklisted.  If the `Handshake`
request cannot be processed for a _recoverable_ reason, then the receiver should
reply with a `Nack` with the appropriate error code to tell the sender to try
again.

When executing a handshake, a peer should _not_ include any other peers in the
`relayers` vector except for itself.  The `relayers` field will be ignored.

### Learning the public IP address

Before the peer can participate in the control plane, it must know its
publicly-routable IP address so it can exchange it with its remote neighbors.
This is necessary, since other neighbors-of-neighbors will learn this peer's
public IP address from its remote neighbors, and thus must have a publicly-routable
address if they are going to handshake with it.

The peer may take an operator-given public IP address.  If no public IP address
is given, the peer will learn the IP address using the `NatPunchRequest` and
`NatPunchReply` messages as follows:

1. The peer sends a `NatPunchRequest` to a randomly-chosen initial neighbor it has
   already handshaked with.  It uses a random nonce value.
2. The remote neighbor replies with a (signed) `NatPunchReply` message, with its
   `addrbytes` and `port` set to what it believes the public IP is (based on the
   underlying socket's peer address).
3. Upon receipt of the `NatPunchReply`, the peer will have confirmed its public
   IP address, and will send it in all future `HandshakeAccept` messages.  It
   will periodically re-learn its IP address, if it was not given by the
   operator.

Because the peer's initial neighbors are chosen by the operator as being
sufficiently trustworthy to supply network information for network walks, it is
reasonable to assume that they can also be trusted to tell a bootstrapping peer
its public IP address.

### Checking a Peer's Liveness

A sender peer can check that a peer is still alive by sending it a `Ping`
message on the control-plane.  The receiver should reply with a `Pong` message.  Both the sender
and receiver peers would update their metrics for measuring each other's
responsiveness, but they do _not_ alter any information about each other's
public keys and expirations.

Peers will ping each other periodically this way to prove that they are still alive.
This reduces the likelihood that they will be removed from each other's
frontiers (see below).

### Exchanging Neighbors

Peers exchange knowledge about their neighbors on the control-plane as follows:

1. The sender peer creates a `GetNeighbors` message and sends it to the
   receiver.
2. The receiver chooses up to 128 neighbors it knows about and replies to the
   sender with them as a `Neighbors` message.  It provides the hashes of their session public keys (if
known) as a hint to the sender, which the sender may use to further
authenticate future neighbors.
3. The sender sends `Handshake` messages to a subset of the replied neighbors,
   prioritizing neighbors that are not known to the sender or have not been
recently contacted.
4. The various neighbors contacted reply either `HandshakeAccept`,
   `HandshakeReject`, or `Nack` messages.  The sender updates its frontier with
knowledge gained from the `HandshakeAccept` messages.

On success, the sender peer adds zero or more of the replied peer addresses to
its frontier set.  The receiver and its contacted neighbors do nothing but
update their metrics for the sender.

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

### Requesting Blocks on the Data-Plane

Peers exchange blocks in a 2-process protocol:  the sender first queries the
receiver for the blocks it has via the control-plane,
and then queries individual blocks and microblocks on the data-plane.

On the control-plane, the sender builds up a locally-cached inventory of which
blocks the receiver has.  To do so, the sender and receiver execute a two-phase
protocol to synchronize the sender's view of the receiver's block inventroy.
First, the sender downloads the receiver's knowledge of PoX reward cycles,
encoded as a bit vector where a `1` in the _ith_ position means that the
receiver is certain about the status of the PoX anchor block in the _ith_ reward
cycle (i.e. it either does not exist, or it does exist and the receiver has a
copy).  It is `0` otherwise -- i.e. it may exist, but the receiver does not have
a copy.

To synchronize the PoX anchor block knowledge, the sender and receiver do the following:

1.  The sender creates a `GetPoxInv` message for the range of PoX reward cycles
    it wants, and sends it to the receiver.
2.  If the receiver recognizes the consensus hash in the `GetPoxInv` message, it
    means that the receiver agrees on all PoX state that the sender does, up to the
burn chain block that this consensus hash represents (note that the consensus
hash must correspond to a burn chain block at the start of a reward cycle).  The receiver replies with
a `PoxInv` with its knowledge of all reward cycles at and after the reward cycle
identified by that consensus hash.
3.  The sender and receiver continue to execute this protocol until the receiver
    shares all of its PoX reward cycle knowledge, or it encounters a consensus
hash from the sender that it does not recognize.  If the latter happens, the
receiver shall reply with a `Nack` with the appropriate error code.

Once the sender has downloaded the PoX anchor block knowledge from the receiver,
it proceeds to fetch an inventory of all block and microblock knowledge from the
receiver for all PoX reward cycles that it agrees with the receiver on.  That
is, it will fetch block and microblock inventory data for all reward cycles in
which the sender and receiver both have a `1` or both have a `0` in the _ith_ bit position,
starting from the first-ever reward cycle, and up to either the lowest reward cycle in
which they do not agree (or the end of the PoX vector, whichever comes first).
They proceed as follows:

1.  The sender creates a `GetBlocksInv` message for reward cycle _i_,
    and sends it to the receiver.
2.  If the receiver has processed the range of blocks represented by the `GetBlocksInv` 
    block range -- i.e. it recognizes the consensus hash in `GetBlocksInv` as
the start of a reward cycle -- then the receiver creates a `BlocksInv` message and replies
with it.  The receiver's inventory bit vectors may be _shorter_ than the
requested range if the request refers to blocks at the burn chain tip.  The
receiver sets the _ith_ bit in the blocks inventory if it has the corresponding
block, and sets the _ith_ bit in the microblocks inventory if it has the
corresponding _confirmed_ microblock stream.
3.  The sender repeats the process for reward cycle _i+1_, so long as both it
    and the receiver are both certain about the PoX anchor block for reward
cycle _i+1_, or both are uncertain.  If this is not true, then the sender stops
downloading block and microblock inventory from the receiver, and will assume
that any blocks in or after this reward cycle are unavailable from the receiver.

The receiver peer may reply with a `PoxInv` or `BlocksInv` with as few
inventory bits as it wants, but it must reply with at
least one inventory bit.  If the receiver does not do so,
the sender should terminate the connection to the receiver and refrain from
contacting it for a time.

While synchronizing the receiver's block inventory, the sender will fetch blocks and microblocks
on the data-plane once it knows that the receiver has them.
To do so, the sender and receiver do the following:

1.  The sender looks up the `data_url` from the receiver's `HandshakeAccept` message
    and issues a HTTP GET request for each anchored block marked as present in
the inventory.
2.  The receiver replies to each HTTP GET request with the anchored blocks.
3.  Once the sender has received a parent and child anchor block, it will ask
    for the microblock stream confirmed by the _child_ by asking for the
microblocks that the child confirms.  It uses the _index hash_ of the child
anchored block to do so, which itself authenticates the last hash in the
confirmed microblock stream.
4.  The receiver replies to each HTTP GET request with the confirmed microblock
    streams.
5.  As blocks and microblock streams arrive, the sender processes them to build
    up its view of the chain.

When the sender receives a block or microblock stream, it validates them against
the burn chain state.  It ensures that the block hashes to a block-commit
message that won sortition (see SIP-001 and SIP-007), and it ensures that a confirmed
microblock stream connects a known parent and child anchored block.  This means
that the sender **does not need to trust the receiver** to validate block data
-- it can receive block data from any HTTP endpoint on the web.

The receiver should reply blocks and confirmed microblock streams if it had
previously announced their availability in a `BlocksInv` message.
If the sender receives no data (i.e. a HTTP 404)
for blocks the receiver claimed to have, or if the sender receives invalid data or 
an incomplete microblock stream, then the sender disconnects from the receiver
and blacklists it on the control-plane.

The sender may not be contracting a peer node when it fetches blocks and
microblocks -- the receiver may send the URL to a Gaia hub in its
`HandshakeAcceptData`'s `data_url` field.  In doing so, the receiver can direct
the sender to fetch blocks and microblocks from a well-provisioned,
always-online network endpoint that is more reliable than the receiver node.

Blocks and microblocks are downloaded incrementally by reward cycle.
As the sender requests and receives blocks and microblocks for reward cycle _i_,
it learns the anchor block for reward cycle _i+1_ (if it exists at all), and
will only then be able to determine the true sequence of consensus hashes for
reward cycle _i+1_.  As nodes do this, their PoX knowledge my change -- i.e.
they will become certain of the presences of PoX anchor blocks that they had
previously been uncertain of.  As such, nodes periodically re-download each
other's PoX inventory vectors, and if they have changed -- i.e. the _ith_ bit flipped
from a `0` to a `1` -- the block and microblock inventory state representing blocks and
microblocks in or after reward cycle _i_ will be dropped and re-downloaded.

### Announcing New Data

In addition to synchronizing inventories, peers announce to one another
when a new block or confirmed microblock stream is available.  If peer A has
crawled peer B's inventories, and peer A downloads or is forwarded a block or
confirmed microblock stream that peer B does not have, then peer A will send a
`BlocksAvailable` (or `MicroblocksAvailable`) message to peer B to inform it
that it can fetch the data from peer A's data plane.  When peer B receives one
of these messages, it updates its copy of peer A's inventory and proceeds to
fetch the blocks and microblocks from peer A.  If peer A serves invalid data, or
returns a HTTP 404, then peer B disconnects from peer A (since this indicates
that peer A is misbehaving).

Peers do not forward blocks or confirmed microblocks to one another.  Instead,
they only announce that they are available.  This minimizes the aggregate
network bandwidth required to propagate a block -- a block is only downloaded
by the peers that need it.

Unconfirmed microblocks and transactions are always forwarded to other peers in order to
ensure that the whole peer network quickly has a full copy.  This helps maximize
the number of transactions that can be included in a leader's microblock stream.

### Choosing Neighbors

The core design principle of the Stacks peer network control-plane is to maximize the entropy
of the peer graph.  Doing so helps ensure that the network's connectivity
avoids depending too much on a small number of popular peers and network edges.
While this may slow down message propagation relative to more structured peer graphs,
the _lack of_ structure is the key to making the Stacks peer network
resilient.

This principle is realized through a randomized neighbor selection algorithm.
This algorithm curates the peer's outbound connections to other peers; inbound
connections are handled separately.

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

To achieve this, the Stacks peer network control-plane is structured as a K-regular random graph,
where _any_ peer may be chosen as a peer's neighbor.  The network forms
a _reachability_ network, with the intention of being "maximally difficult" for a
network adversary to disrupt by way of censoring individual nodes and network
hops.  A random graph topology is suitable for this,
since the possibility that any peer may be a neighbor means that the only way to
cut off a peer from the network is to ensure it never discovers another honest
peer.

To choose their neighbors in the peer graph, peers maintain two views of the network:

* The **frontier** -- the set of peers that have either sent a message to this
  peer or have responded to a request at some point in the past.
The size of the frontier is significantly larger than
K.  Peer records in the frontier set may expire and may be stale, but are only
evicted when the space is needed.  The **fresh frontier set** is the subset of
the frontier set that have been successfully contacted in the past _L_ seconds.

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

To construct a K-regular random graph topology, peers execute a modified Metropolis-Hastings
random graph walk with delayed acceptance (MHRWDA) [1] to decide which peers belong to
their neighbor set and to grow their frontiers.

A peer keeps track of which peers are neighbors of which other peers, and in
doing so, is able to calculate the degree of each peer as the number of that
peer's neighbors that report the peer in question as a neighbor.  Given a currently-visited
peer _P_, a neighboring peer _N_ is walked to with probability proportional to
the ratio of their degrees.  The exact formula is adapted from Algorithm 2 in
[1].

Once established, a peer tries to keep its neighbor set stable as long as the
neighbors are live.  It does so by periodically pinging and re-handshaking with
its K neighbors in order to establish a minimum time between contacts.
As it communicates with neighbors, it will measure the health of each neighbor by measuring how often
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
nodes and edges are likely to be online by examining its fresh frontier set.

The frontier set grows whenever new neighbors are discovered, but it is not
infinitely large.  Frontier nodes are stored in a bound-sized hash table on disk.  A neighbor
inserted deterministically into the frontier set by hashing its address with a
peer-specific secret and the values `0` through `7` in order to identify eight
slots into which its address can be inserted.  If any of the resulting slots are
empty, the peer is added to the frontier.

As more peers are discovered, it becomes possible that a newly-discovered peer cannot be inserted
determinstically.  This will become more likely than not to happen once the
frontier set has `8 * sqrt(F)` slots full, where `F` is the maximum size of
the frontier (due to the birthday paradox).  In such cases, a random existing peer in one of the slots is
chosen for possible eviction, but only if it is offline.  The peer will attempt
to handshake with the existing peer before evicting it, and if it responds with
a `HandshakeAccept`, the new node is discarded and no eviction takes place.

Insertion and deletion are deterministic (and in deletion's case, predicated on
a failure to ping) in order to prevent malicious remote peers from filling up
the frontier set with junk without first acquiring the requisite IP addresses
and learning the victim's peer-specific secret nonce.
The handshake-then-evict test is in place also to
prevent peers with a longer uptime from being easily replaced by short-lived peers.

**Mapping the Peer Network**

The Stacks protocol includes a route recording mechanism for peers to probe network paths.
This is used to measure how frequently peers and connections are used in the peer
graph.  This information is encoded in the `relayers` vector in each message.

When relaying data, the relaying peer must re-sign the message preamble and update its
sequence number to match each recipient peer's expectations on what the signature 
and message sequence will be.  In addition, the relaying peer appends the
upstream peer's address and previous sequence number in the
message's `relayers` vector.  Because the `relayers` vector grows each time a
message is forwarded, the peer uses it to determine the message's time-to-live:
if the `relayers` vector becomes too long, the message is dropped.

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

A peer must not forward messages with invalid `relayers` vectors.  In
particular, if a peer detects that its address (specicifically, it's public key
hash) is present in the `relayers` vector, or if the vector contains a cycle,
then the message _must_ be dropped.  In addition, a peer that receives a message
from an upstream peer without the `SERVICE_RELAY` bit set that includes a
`relayers` vector _must_ drop the message.

**Promoting Route Diversity**

The peer network employs two heuristics to help prevent choke points from
arising:

* Considering the AS-degree:  the graph walk algorithm will consider a peer's
connectivity to different _autonomous systems_
(ASs) when considering adding it to the neighbor set.

* Sending data in rarest-AS-first order:  the relay algorithm will probabilistically
  rank its neighbors in order by how rare their AS is in the fresh frontier set.

When building up its K neighbors, a peer has the opportunity to select neighbors
based on how popular their ASs are.  To do this, the peer crawl N > K neighbors, and then
randomly disconnect from N - K of them.  The probability that a peer will
be removed is proportional to (1) how popular its AS
is in the N neighbors, and (2) how unhealthy it is out of the neighbors in the
same AS.  The peer will first select an AS to prune, and then select a neighbor
within that AS.  This helps ensure that a relayed messasge is likely to be
forwarded to many different ASs quickly.

To forward messages to as many different ASs as possible, the peer will
probabilistically prioritize neighbors to receive a forwarded message based on how _rare_
their AS is in the fresh frontier set.  This forwarding heuristic is
meant to ensure that a message quickly reaches many different networks in the
Internet.

The rarest-AS-first heuristic is implemented as follows:

1. The peer builds a table `N[AS]` that maps its fresh frontier set's ASs to the list of peers
   contained within.  `len(N[AS])` is the number of fresh frontier peers in `AS`, and 
   `sum(len(N[AS]))` for all `AS` is `K`.
2. The peer assigns each neighbor a probability of being selected to receive the
   message next.  The probability depends on `len(N[AS])`, where `AS` is the
   autonomous system ID the peer resides in.  The probability that a peer is
   selected to receive the message is proportional to `1 - (len(N[AS]) + 1) / K`.
3.  The peer selects a neighbor according to the distribution, forwards the message to it, and
    removes the neighbor from consideration for this message.  The peer repeats step 2 until all neighbors have
    been sent the message.

A full empirical evaluation on the effectiveness of these heuristics at encouraging
route diversity will be carried out before this SIP is accepted.

**Proposal for Miner-Assisted Peer Discovery**

Stacks miners are already incentivized to maintain good connectivity with one
another and with the peer network in order to ensure that they work on the
canonical fork.  As such, a correct miner may, in the future, help the
control-plane network remain connected by broadcasting the root of a Merkle tree of a set
of "reputable" peers that are known by the miner to be well-connected, e.g. by
writing it to its block's coinbase payload.  Other
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

### Forwarding Data

The Stacks peer network propagates blocks, microblocks, and
transactions by flooding them.  In particular, a peer can send other peers
an unsolicited `BlocksAvailable`, `MicroblocksAvailable`, `BlocksData`, `MicroblocksData`,
and `Transaction` message.

If the message has not been seen before by the peer, and the data is valid, then the peer
forwards it to a subset of its neighbors (excluding the one that sent the data). 
If it has seen the data before, it does not forward
it.  The process for determining whether or not a block or transaction is valid
is discussed in SIP 005.  However, at a high level, the following
policies hold:

* A `StacksBlock` can only be valid if it corresponds to block commit
  transaction on the burn chain that won sortition.  A peer may cache a
`StacksBlock` if it determines that it has not yet processed the sortition that
makes it valid.  A `StacksBlock` is never forwarded by the recipient;
instead, the recipient peer sends a `BlocksAvailable` message to its neighbors.
* A `StacksMicroblock` can only be valid if it corresponds to a valid
  `StacksBlock` or a previously-accepted `StacksMicroblock`.  A peer may cache a
`StacksMicroblock` if it determines that a yet-to-arrive `StacksBlock` or
`StacksMicroblock` could make it valid in the near-term, but if the
`StacksMicroblock`'s parent `StacksBlock` is unknown, the
`StacksMicroblock` will _not_ be forwarded.
* A `Transaction` can only be valid if it encodes a legal state transition on
  top of the peer's currently-known canonical Stacks blockchain tip. 
A peer will _neither_ cache _nor_ relay a `Transaction` message if it cannot 
determine that it is valid.

#### Client Peers

Messages can be forwarded to both outbound connections to other neighbors and to inbound
connections from clients -- i.e. remote peers that have this peer as a next-hop
neighbor.  Per the above text, outbound neighbors are selected as the
next message recipients based on how rare their AS is in the frontier.

Inbound peers are handled separately.  In particular, a peer does not crawl
remote inbound connections, nor does it synchronize their peers' block inventories.
Inbound peers tend to be un-routable peers, such as those running behind NATs on
private, home networks.  However, such peers can still send
unsolicited blocks, microblocks, and transactions to publicly-routable
peers, and those publicly-routable peers will need to forward them to both its
outbound neighbors as well as its own inbound peers.  To do the latter, 
a peer will selectively forward data to its inbound peers in a way that is
expected to minimize the number of _duplicate_ messages the other peers will
receive.

To do this, each peer uses the `relayers` vector in each message
it receives from an inbound peer to keep track of which peers have forwarded 
the same messages.  It will then choose inbound peers to receive a forwarded message
based on how _infrequently_ the inbound recipient has sent duplicate messages.

The intuition is that if an inbound peer forwards many messages 
that this peer has already seen, then it is likely that the inbound per is also 
connected to a (unknown) peer that is already able to forward it data.
That is, if peer B has an inbound connectino to peer A, and
peer A observes that peer B sends it messeges that it has already seen recently,
then peer A can infer that there exists an unknown peer C that is forwarding
messages to peer B before peer A can do so.  Therefore, when selecting inbound
peers to receive a message, peer A can de-prioritize peer B based on the
expectation that peer B will be serviced by unknown peer C.

To make these deductions, each peer maintains a short-lived (i.e. 10 minutes)
set of recently-seen message digests, as well as the list of which peers have sent 
each message.  Then, when selecting inbound peers to receive a message, the peer
calculates for each inbound peer a "duplicate rank" equal to the number of times
it sent an already-seen message.  The peer then samples the inbound peers
proportional to `1 - duplicate_rank / num_messages_seen`.

It is predicted that there will be more NAT'ed peers than public peers.
Therefore, when forwarding a message, a peer will select more inbound peers
(e.g. 16) than outbound peers (e.g. 8) when forwarding a new message.

## Reference Implementation

Implemented in Rust.  The neighbor set size K is set to 16.  The frontier set size
is set to hold 2^24 peers (with evictions becoming likely after insertions once
it has 32768 entries).

[1] See https://arxiv.org/abs/1204.4140 for details on the MHRWDA algorithm.
[2] https://stuff.mit.edu/people/medard/rls.pdf
