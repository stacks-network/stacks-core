# SIP 004 Cryptographic Committment to Materialized Views

## Preamble

Title: Cryptograhpic Commitment to Materialized Views

Author: Jude Nelson <jude@blockstack.com>

Status: Draft

Type: Standard

Created: 7/15/2019

License: BSD 2-Clause

## Abstract

Blockchain peers are replicated state machines, and as such, must maintain a
materialized view of all of the state the transaction log represents in order to
validate a subsequent transaction.  The Stacks blockchain in particular not only
maintains a materialized view of the state of every fork, but also requires
miners to cryptographically commit to that view whenever they mine a block.
This document describes a **Merklized Adaptive Radix Forest** (MARF), an
authenticated index data structure for efficiently encoding a 
cryptographic commitment to blockchain state.

The MARF's structure is part of the consensus logic in the Stacks blockchain --
every Stacks peer must process the MARF the same way.  Stacks miners announce
a cryptographic hash of their chain tip's MARF in the blocks they produce, and in
doing so, demonstrate to each peer and each light client that they have 
applied the block's transactions to the peer's state correctly.

The MARF represents blockchain state as an authenticated directory.  State is
represented as key/value pairs.  The MARF structure gives a peer the ability to
prove to a light client that a particular key has a particular value, given the
MARF's cryptographic hash.  The proof has _O(log B)_ space for _B_ blocks, and
takes _O(log B)_ time complexity to produce and verify.  In addition, it offers
_O(1)_ expected time and space complexity for inserts and queries.
The MARF proof allows a light client to determine:

* What the value of a particular key is,
* How much cumulative energy has been spent to produce the key/value pair,
* How many confirmations the key/value pair has.

## Rationale

In order to generate a valid transaction, a blockchain client needs to be able
to query the current state of the blockchain.  For example, in Bitcoin, a client
needs to query its unspent transaction outputs (UTXOs) in order to satisfy their
spending conditions in a new transaction.  As another example, in Ethereum, a
client needs to query its accounts' current nonces in order to generate a valid
transaction to spend their tokens.

Whether or not a blockchain's peers are required to commit to the current state
in the blocks themselves (i.e. as part of the consensus logic) is a
philosophical decision.  We argue that it is a highly desirable in Blockstack's
case, since it affords light clients more security when querying the blockchain state than
not.  This is because a client often queries state that was last updated several
blocks in the past (i.e. and is "confirmed").  If a blockchain peer can prove to
a client that a particular key in the state has a particular value, and was last
updated a certain number of blocks in the past, then the client can determine
whether or not to trust the peer's proof based on factors beyond simply trusting
the remote peer to be honest.  In particular, the client can determine how
difficult it would be to generate a dishonest proof, in terms of the number of
blocks that would need to be maliciously crafted and accepted by the network.
This offers clients some protection against peers that would lie to them -- a
lying peer would need to spend a large amount of energy (and money) in order to
do so.

Specific to Blockstack, we envision that many applications will run
their own Stacks-based blockchain peer networks that operate "on top" of the
Stacks blockchain through proof-of-burn.  This means that the Blockstack
application ecosystem will have many parallel "app chains" that users may wish
to interact with.  While a cautious power user may run validator nodes for each
app chain they are interested in, we expect that most users will not do so,
especially if they are just trying out the application or are casual users.  In
order to afford these users better security than simply telling them to find a
trusted validating peer, it is essential that each Stacks peer commits to its
materialized view in each block.

On top of providing better security to light clients, committing to the materialized
state view in each block has the additional benefit of helping the peer network
detect malfunctioning miners early on.  A malfunctioning miner will calculate a
different materialized view using the same transactions, and with overwhelmingly
high probability, will also calculate a different state view hash.  This makes
it easy for a blockchain's peers to reject a block produced in this manner
outright, without having to replay its transactions.

### Design Considerations

Committing to the materialized view in each block has a non-zero cost in terms
of time and space complexity.  Given that Stacks miners use PoW to increase
their chances of winning a block race, the time required to calculate
the materialized view necessarily cuts into the time
required to solve the PoW puzzle -- it is part of the block validation logic.
While this is a cost borne by each miner, the fact that PoW mining is a zero-sum game
means that miners that are able to calculate the materialized view the fastest will have a
better chance of winning a block race than those who do not.  This means that it
is of paramount importance to keep the materialized view digest calculation as
fast as possible, just as it is of paramount importance to make block
validation as fast and cheap as possible.

The following considerations have a non-trivial impact on the design of the
MARF:

**A transaction can read or write any prior state in the same fork.**  This
means that the index must support fast random-access reads and fast
random writes.

**The Stacks blockchain can fork, and a miner can produce a fork at any block
height in the past.**  As argued in SIP 001, a Stacks blockchain peer must process
all forks and keep their blocks around.  This also means that a peer needs to
calculate and validate the materialized view of each fork, no matter where it
occurs.  This is also necessary because a client may request a proof for some
state in any fork -- in order to service such requests, the peer must calculate
the materialized view for all forks.

**Forks can occur in any order, and blocks can arrive in any order.**  As such,
the runtime cost of calculating the materialized view must be _independent_ of the
order in which forks are produced, as well as the order in which their blocks
arrive.  This is required in order to avoid denial-of-service vulnerabilities,
whereby a network attacker can control the schedules of both
forks and block arrivals in a bid to force each peer to expend resources
validating the fork.  It must be impossible for an attacker to
significantly slow down the peer network by maliciously varying either schedule.
This has non-trivial consequences for the design of the data structures for
encoding materialized views.

## Specification

The Stacks peer's materialized view is realized as a flat key/value store.
Transactions encode zero or more creates, inserts, updates, and deletes on this
key/value store.  As a consequence of needing to support forks from any prior block,
no data is ever removed; instead, a "delete" on a particular key is encoded 
by replacing the value with a tombstone record.  The materialized view is the
subset of key/value pairs that belong to a particular fork in the blockchain.

The Stacks blockchain separates the concern of maintaining _authenticated
index_ over data from storing a copy of the data itself.  The blockchain peers
commit to the digest of the authenticated index, but can store the data however
they want.  The authenticated index is realized as a _Merklized Adaptive Radix
Forest_ (MARF).  The MARF gives Stacks peers the ability to prove that a
particular key in the materialized view maps to a particular value in a
particular fork.

A MARF has two principal data structures:  a _merklized adaptive radix trie_
for each block and a _merklized skip-list_ that
cryptographically links merklized adaptive radix tries in prior blocks to the
current block.

### Merklized Adaptive Radix Tries (ARTs)

An _adaptive radix trie_ (ART) is a prefix tree where each node's branching
factor varies with the number of children.  In particular, a node's branching
factor increases according to a schedule (0, 4, 16, 48, 256) as more and more
children are added.  This behavior, combined with the usual sparse trie
optimizations of _lazy expansion_ and _path compression_, produce a tree-like
index over a set key/value pairs that is _shallower_ than a perfectly-balanced
binary search tree over the same values.  Details on the analysis of ARTs can
be found in [1].

To produce an _index_ over new state introduced in this block, the Stacks peer
will produce an adaptive radix trie that describes each key/value pair modified.
In particular, for each key affected by the block, the Stacks peer will:
* Calculate the hash of the key to get a fixed-length trie path,
* Store the new value and this hash into its data store,
* Insert or update the associated value hash in the block's ART at the trie path,
* Calculate the new Merkle root of the ART by hashing all modified intermediate
  nodes along the path.

In doing so, the Stacks peer produces an authenticated index for all key/value
pairs affected by a block.  The leaves of the ART are the hashes of the values,
and the hashes produced in each intermediate node and root give the peer a
way to cryptographically prove that a particular value is present in the ART
(given the root hash and the key).

The Stacks blockchain employs _path compression_ and _lazy expansion_
to efficiently represent all key/value pairs while minimizing the number of trie
nodes.  That is, if two children share a common prefix, the prefix bytes are
stored in a single intermediate node instead of being spread across multiple
intermediate nodes (path compression).  In the special case where a path suffix
uniquely identifies the leaf, the path suffix will be stored alongside the leaf
instead as a sequence of intermediate nodes (lazy expansion).  As more and more
key/value pairs are inserted, intermediate nodes and leaves with multi-byte
paths will be split into more nodes.

**Trie Structure**

A trie is made up of nodes with radix 4, 16, 48, or 256, as well as leaves.  In
the documentation below, these are called `node4`, `node16`, `node48`,
`node256`, and `leaf` nodes.  An empty trie has a single `node256` as its root.
Child pointers occupy one byte.

**Notation**

The notation `(ab)node256` means "a `node256` who descends from its parent via
byte 0xab".

The notation `node256[path=abcd]` means "a `node256` that has a shared prefix
with is children `abcd`".

**Lazy Expansion**

If a leaf has a non-zero-byte path suffix, and another leaf is inserted that
shares part of the suffix, the common bytes will be split off of the existing
leaf to form a `node4`, whose two immediate children are the two leaves.  Each
of the two leaves will store the path bytes that are unique to them.  For
example, consider this trie with a root `node256` and a single leaf, located at
path `aabbccddeeff00112233` and having value hash `123456`:

```
node256
       \
        (aa)leaf[path=bbccddeeff00112233]=123456
```

If the peer inserts the value hash `98765` at path `aabbccddeeff998877`, the
single leaf's path will be split into a shared prefix and two distinct suffixes,
as follows:

```
insert (aabbccddeeff998877, 98765)

node256                            (00)leaf[path=112233]=123456
       \                          /
        (aa)node4[path-bbccddeeff]
                                  \
                                   (99)leaf[path=887766]=98765
```

Now, the trie encodes both `aabbccddeeff00112233=123456` and
`aabbccddeeff99887766=98765`.

**Node Promotion**

As a node with a small radix gains children, it will eventually need to be
promoted to a node with a higher radix.  A `node4` will become a `node16` when
it receives its 5th child; a `node16` will become a `node48` when it receives
its 17th child, and a `node48` will become a `node256` when it receives its 49th
child.  A `node256` will never need to be promoted, because it has slots for
child pointers with all possible byte values.

For example, consider this trie with a `node4` and 4 children:

```
node256                                (00)leaf[path=112233]=123456
       \                              /
        \                            /  (01)leaf[path=445566]=67890
         \                          /  /
          (aa)node4[path=bbccddeeff]---
                                    \  \
                                     \  (02)leaf[path=778899]=abcdef
                                      \
                                       (99)leaf[path=887766]=98765
```

This trie encodes the following:
   * `aabbccddeeff00112233=123456`
   * `aabbccddeeff01445566=67890`
   * `aabbccddeeff02778899=abcdef`
   * `aabbccddeeff99887766=9876`

Inserting one more node with a prefix `aabbccddeeff` will promote the
intermediate `node4` to a `node16`:

```
insert (aabbccddeeff03aabbcc, 314159)

node256                                 (00)leaf[path=112233]=123456
       \                               /
        \                             /  (01)leaf[path=445566]=67890
         \                           /  /
          (aa)node16[path=bbccddeeff]-----(03)leaf[path=aabbcc]=314159
                                     \  \
                                      \  (02)leaf[path=778899]=abcdef
                                       \
                                        (99)leaf[path=887766]=98765
```

The trie now encodes the following:
   * `aabbccddeeff00112233=123456`
   * `aabbccddeeff01445566=67890`
   * `aabbccddeeff03aabbcc=314159`
   * `aabbccddeeff02778899=abcdef`
   * `aabbccddeeff99887766=9876`

**Path Compression**

Intermediate nodes, such as the `node16` in the previous example, store path
prefixes shared by all of their children.  If a node is inserted that shares
some of this prefix, but not all of it, the path is "decompressed" -- a new
leaf is "spliced" into the compressed path, and attached to a `node4` whose two
children are the leaf and the existing node (i.e. the `node16` in this case)
whose shared path now contains the suffix unique to its children, but distinct
from the newly-spliced leaf.

For example, consider this trie with the intermediate `node16` sharing a path
prefix `bbccddeeff` with its 5 children:

```
node256                                 (00)leaf[path=112233]=123456
       \                               /
        \                             /  (01)leaf[path=445566]=67890
         \                           /  /
          (aa)node16[path=bbccddeeff]-----(03)leaf[path=aabbcc]=314159
                                     \  \
                                      \  (02)leaf[path=778899]=abcdef
                                       \
                                        (99)leaf[path=887766]=98765
```

This trie encodes the following:
   * `aabbccddeeff00112233=123456`
   * `aabbccddeeff01445566=67890`
   * `aabbccddeeff03aabbcc=314159`
   * `aabbccddeeff02778899=abcdef`
   * `aabbccddeeff99887766=9876`

If we inserted `(aabbcc001122334455, 21878)`, the `node16`'s path would be
decompressed to `eeff`, a leaf with the distinct suffix `1122334455` would be spliced
in via a `node4`, and the `node4` would have the shared path prefix `bbcc` with
its now-child `node16` and leaf.

```
insert (aabbcc00112233445566, 21878)

                               (00)leaf[path=112233445566]=21878
                              /
node256                      /                       (00)leaf[path=112233]=123456
       \                    /                       /
        (aa)node4[path=bbcc]                       /  (01)leaf[path=445566]=67890
                            \                     /  /
                             (dd)node16[path=eeff]-----(03)leaf[path=aabbcc]=314159
                                                  \  \
                                                   \  (02)leaf[path=778899]=abcdef
                                                    \
                                                     (99)leaf[path=887766]=98765
```

The resulting trie now encodes the following:
   * `aabbcc00112233445566=21878`
   * `aabbccddeeff00112233=123456`
   * `aabbccddeeff01445566=67890`
   * `aabbccddeeff03aabbcc=314159`
   * `aabbccddeeff02778899=abcdef`
   * `aabbccddeeff99887766=9876`

### Back-pointers

The materialized view of a fork will hold key/value pairs for data produced by
applying _all transactions_ in that fork, not just the ones in the last block.  As such,
the index over all key/value pairs in a fork is encoded in the sequence of 
its block's merklized ARTs.

To ensure that random reads and writes on the a fork's materialized view remain
fast no matter which block added them, a child pointer in an ART can point to
either a node in the same ART, or a node with the same path in a prior ART.  For
example, if the ART at block _N_ has a `node16` whose path is `aabbccddeeff`, and 10
blocks ago a leaf was inserted at path `aabbccddeeff99887766`, it will
contain a child pointer to the intermediate node from 10 blocks ago whose path is
`aabbccddeeff` and who has a child node in slot `0x99`.  This information is encoded
as a _back-pointer_.  To see it visually:

```
At block N


node256                                 (00)leaf[path=112233]=123456
       \                               /
        \                             /  (01)leaf[path=445566]=67890
         \                           /  /
          (aa)node16[path=bbccddeeff]-----(03)leaf[path=aabbcc]=314159
                                     \  \
                                      \  (02)leaf[path=778899]=abcdef
                                       \
                                        |
                                        |
                                        |
At block N-10 - - - - - - - - - - - - - | - - - - - - - - - - - - - - - - - - -
                                        |
node256                                 | /* back-pointer to block N-10 */
       \                                |
        \                               |
         \                              |
          (aa)node4[path=bbccddeeff]    |
                                    \   |
                                     \  |
                                      \ |
                                       (99)leaf[path=887766]=98765
```

By maintaining trie child pointers this way, the act of looking up a path to a value in
a previous block is a matter of following back-pointers to previous tries.
This back-pointer uses the _block-hash_ of the previous block to uniquely identify
the block. In order to keep the in-memory and on-disk representations of trie nodes succint,
the MARF structure uses a locally defined unsigned 32-bit integer to identify the previous 
block, along with a local mapping of such integers to the respective block header hash.

Back-pointers are calculated in a copy-on-write fashion when calculating the ART
for the next block.  When the root node for the ART at block N+1 is created, all
of its children are set to back-pointers that point to the immediate children of
the root of block N's ART.  Then, when inserting a key/value pair, the peer
walks the current ART to the insertion point, but whenever a
back-pointer is encountered, it copies the node it points to into the current
ART, and sets all of its non-empty child pointers to back-pointers.  The peer
then continues traversing the ART until the insertion point is found (i.e. a
node has an unallocated child pointer where the leaf should go), copying
over intermediate nodes lazily.

For example, consider the act of inserting `aabbccddeeff00112233=123456` into an
ART where a previous ART contains the key/value pair
`aabbccddeeff99887766=98765`:

```
At block N


node256                                (00)leaf[path=112233]=123456
^      \                              /
|       \                            /
|        \                          /
|         (aa)node4[path=bbccddeeff]
|                 ^                 \
|                 |                  \
| /* 1. @root. */ | /* 2. @node4.  */ \  /* 3. 00 is empty, so insert */
| /* copy up, &*/ | /* copy up, &  */  |
| /* make back-*/ | /* make back-  */  |
| /* ptr to aa */ | /* ptr to 99   */  |
|                 |                    |
|- At block N-10 -|- - - - - - - - - - | - - - - - - - - - - - - - - - - - -
|                 |                    |
node256           |                    |
       \          |                    |
        \         |                    |
         \        |                    |
          (aa)node4[path=bbccddeeff]   |
                                    \  |
                                     \ |
                                      \|
                                       (99)leaf[path=887766]=98765
```

In step 1, the `node256` in block _N_ would have a back-pointer to the `node4` in
block _N - 10_ in child slot `0xaa`.  While walking path `aabbccddeeff00112233`,
the peer would follow slot `0xaa` to the `node4` in block _N - 10_ and copy it
into block _N_, and would set its child pointer at `0x99` to be a back-pointer
to the `leaf` in block _N - 10_.  It would then step to the `node4` it copied,
and walk path bytes `bbccddeeff`.  When it reaches child slot `0x00`, the peer
sees that it is unallocated, and attaches the leaf with the unexpanded path
suffix `112233`.  The back-pointer to `aabbccddeeff99887766=98765` is thus
preserved in block _N_'s ART.

**Calculating the Root Hash with Back-pointers**

For reasons that will be explained in a moment, the hash of a child node that is a
back-pointer is not calculated the usual way when calculating the root hash of
the Merklized ART.  Instead of taking the hash of the child node (as would be
done for a child in the same ART), the hash of the _block header_ is used
instead.  In the above example, the hash of the `leaf` node whose path is
`aabbccddeeff99887766` would be the hash of block _N - 10_'s header, whereas the
hash of the `leaf` node whose path is `aabbccddeeff00112233` would be the hash
of the value hash `123456`.

The main reason for doing this is to keep block validation time down by a
significant constant factor.  The block header hash is always kept in RAM,
but at least one disk seek is required to read the hash of a child in a separate
ART (and it often takes more than one seek). This does not sacrifice the security
of a Merkle proof of `aabbccddeeff99887766=98765`, but it does alter the mechanics
of calculating and verifying it.

### Merklized Skip-list

The second principal data structure in a MARF is a Merklized skip-list encoded
from the block header hashes and ART root hashes in each block.  The hash of the
root node in the ART for block _N_ is derived not only from the hash of the
root's children, but also from the hashes of the block headers from blocks
`N - 1`, `N - 2`, `N - 4`, `N - 8`, `N - 16`, and so on.  This constitutes
a _Merklized skip-list_ over the sequence of ARTs.

The reason for encoding the root node's hash this way is to make it possible for
peers to create a cryptographic proof that a particular key maps to a particular
value when the value lives in a prior block, and can only be accessed by
following one or more back-pointers.  In addition, the Merkle skip-list affords
a client _two_ ways to verify key-value pairs:  the client only needs either (1)
a known-good root hash, or (2) the sequence of block headers for the Stacks
chain and its underlying burn chain.  Having (2) allows the client to determine
(1), but calculating (2) is expensive for a client doing a small number of
queries.  For this reason, both options are supported.

#### Resolving Block Height Queries

For a variety of reasons, the MARF structure must be able to resolve
queries mapping from block heights (or relative block heights) to
block header hashes and vice-versa --- for example, the Clarity VM
allows contracts to inspect this information. Most applicable to the
MARF, though, is that in order to find the ancestor hashes to include
in the Merklized Skip-list, the data structure must be able to find
the block headers which are 1, 2, 4, 8, 16, ... blocks prior in the
same fork. This could be discovered by walking backwards from the
current block, using the previous block header to step back through
the fork's history. However, such a process would require _O(N)_ steps
(where _N_ is the current block height). But, if a mapping exists for
discovering the block at a given block height, this process would instead
be _O(1)_ (because a node will have at most 32 such ancestors).

But correctly implementing such a mapping is not trivial: a given
height could resolve to different blocks in different forks. However,
the MARF itself is designed to handle exactly these kinds of
queries. As such, at the beginning of each new block, the MARF inserts
into the block's trie two entries:

1. This block's block header hash -> this block's height.
2. This block's height -> this block's block header hash.

This mapping allows the ancestor hash calculation to proceed.

### MARF Merkle Proofs

A Merkle proof for a MARF is constructed using a combination of two types of
sub-proofs:  _segment proofs_, and _shunt proofs_.  A _segment proof_ is a proof
that a node belongs to a particular Merklized ART.  It is simply a Merkle tree
proof.  A _shunt proof_ is a proof that the ART for block _N_ is exactly _K_
blocks away from the ART at block _N - K_.  It is generated as a Merkle proof
from the Merkle skip-list.

Calculating a MARF Merkle proof is done by first calculating a segment proof for a
sequence of path prefixes, such that all the nodes in a single prefix are in the
same ART.  To do so, the node walks from the current block's ART's root node
down to the leaf in question, and each time it encounters a back-pointer, it
generates a segment proof from the _currently-visited_ ART to the intermediate
node whose child is the back-pointer to follow.  If a path contains _i_
back-pointers, then there will be _i+1_ segment proofs.

Once the peer has calculated each segment proof, it calculates a shunt proof
that shows that the _i+1_th segment was reached by walking back a given number
of blocks from the _i_th segment by following the _i_th segment's back-pointer.
The final shunt proof for the ART that contains the leaf node includes all of
the prior block header hashes that went into producing its root node's hash.
Each shunt proof is a sequence of sequences of block header hashes and ART root
hashes, such that the hash of the next ART root node can be calculated from the
previous sequence.

For example, consider the following ARTs:

```
At block N


node256                                 (00)leaf[path=112233]=123456
       \                               /
        \                             /  (01)leaf[path=445566]=67890
         \                           /  /
          (aa)node16[path=bbccddeeff]-----(03)leaf[path=aabbcc]=314159
                                     \  \
                                      \  (02)leaf[path=778899]=abcdef
                                       \
                                        |
                                        |
                                        |
At block N-10 - - - - - - - - - - - - - | - - - - - - - - - - - - - - - - - - -
                                        |
node256                                 | /* back-pointer to N - 10 */
       \                                |
        \                               |
         \                              |
          (aa)node4[path=bbccddeeff]    |
                                    \   |
                                     \  |
                                      \ |
                                       (99)leaf[path=887766]=98765
```

To generate a MARF Merkle proof, the client queries a Stacks peer for a
particular value hash, and then requests the peer generate a proof that the key
and value must have been included in the calculation of the current block's ART
root hash (i.e. the digest of the materialized view of this fork). 

For example, given the key/value pair `aabbccddeeff99887766=98765` and the hash
of the ART at block _N_, the peer would generate two segment proofs for the
following paths: `aabbccddeeff` in block _N_, and `aabbccddeeff99887766` in
block `N - 10`.

```
At block N


node256
       \   /* this segment proof would contain the hashes of all other */
        \  /* children of the root, except for the one at 0xaa.        */
         \
          (aa)node16[path=bbccddeeff]

At block N-10 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

node256    /* this segment proof would contain two sequences of hashes: */
       \   /* the hashes for all children of the root besides 0xaa, and */
        \  /* the hashes of all children of the node4, except 0x99.     */
         \
          (aa)node4[path=bbccddeeff]
                                    \
                                     \
                                      \
                                       (99)leaf[path=887766]=98765
```

Then, it would calculate two shunt proofs.  The first proof, called the "head shunt proof,"
supplies the sequence of block hashes for blocks _N - 11, N - 12, N - 14, N - 18, N - 26, ..._ and the 
hash of the children of the root node of the ART for block _N - 10_.  This lets the 
client calculate the hash of the root of the ART at block _N - 10_.  The second
shunt proof (and all subsequent shunt proofs, if there are more back-pointers to
follow) is comprised of the hashes that "went into" calculating the hashes on the
skip-list from the next segment proof's root hash.

In detail, the second shunt proof would have two parts:

* the block header hashes for block _N - 9_ _N - 12_, _N - 16_, _N - 24_, ...
* the block header hashes for _N - 1_, _N - 2_, _N - 4_, _N - 16_, _N - 32_, ...

The reason there are two sequences in this shunt proof is because "walking back"
from block _N_ to block _N - 10_ requires walking first to block _N - 8_ (i.e.
following the skip-list column for 2 ** 3), and then walking to block _N - 10_
from _N - 8_ (i.e. following its skip-list column for 2 ** 1).  The first segment
proof (i.e. with the leaf) lets the client calculate the hash of the children of
the ART root node in block _N - 10_, which when combined with the first part of
this shunt proof yields the ART root hash for _N - 8_.  Then, the client
uses the hash of the children of the root node in the ART of block _N_ (calculated from the second segment
proof), combined with the root hash from node _N - 8_ and with the hashes
in the second piece of this shunt proof, to calculate the ART root hash for
block _N_.  The proof is valid if this calculated root hash matches the root
hash for which it requested the proof.

In order to fully verify the MARF Merkle proof, the client would verify that:

* The first segment proof's path's bytes are equal to the hash of the key for
  which the proof was requested.
* The first segment proof ends in a leaf node, and the leaf node contains the
  hash of the value for which the proof was requested.
* Each segment proof is valid -- the root hash could only be calculated from the
  deepest intermediate node in the segment,
* Each subsequent segment proof was generated from a prefix of the path
  represented by the current segment proof,
* Each back-pointer at the tail of each segment (except the one that terminates
  in the leaf -- i.e. the first one) was a number of blocks back that is equal
  to the number of blocks skipped over in the shunt proof linking it to the next
  segment.
* Each block header was included in the fork the client is querying,
* Each block header was generated from its associated ART root hash,
* (Optional, but encouraged): The burn chain block headers demonstrate that the
  correct difficulty rules were followed.  This step can be skipped if the
client somehow already knows that the hash of block _N_ is valid.

Note that to verify the proof, the client would need to substitute the
_block header hash_ for each intermediate node at the tail of each segment
proof.  The block header hash can either be obtained by fetching the block
headers for both the Stacks chain and burn chain _a priori_ and verifying that
they are valid, or by fetching them on-the-fly.  The second strategy should only
be used if the client's root hash it submits to the peer is known out-of-band to
be the correct hash.

The security of the proof is similar to SPV proofs in Bitcoin -- the proof is
valid assuming the client is able to either verify that the final header hash
represents the true state of the network, or the client is able to fetch the
true burn chain block header sequence.  The client has some assurance that a
_given_ header sequence is the _true_ header sequence, because the header
sequence encodes the proof-of-work that went into producing it.  A header
sequence with a large amount of proof-of-work is assumed to be infeasible for an
attacker to produce -- i.e. only the majority of the burn chain's network hash
power could have produced the header chain.  Regardless of which data the client
has, the usual security assumptions about confirmation depth apply -- a proof
that a key maps to a given value is valid only if the transaction that set
it is unlikely to be reversed by a chain reorg.

### Performance

The time and space complexity of a MARF is as follows:

* **Reads are _O(1)_** While reads may traverse multiple tries, they are always
  descending the radix trie, and resolving back pointers is constant time.
* **Inserts and updates are _O(1)._** Inserts have the same complexity
  as reads, though they require more work by constant factors (in
  particular, hash recalculations).
* **Creating a new block is _O(log B)_.** Inserting a block requires
  including the Merkle skip-list hash in the root node of the new
  ART. This is _log B_ work, where _B_ is chain length.
* **Creating a new fork is _O(log B)_.** Forks do not incur any overhead relative
  to appending a block to a prior chain-tip.
* **Generating a proof is _O(log B)_ for B blocks**.  This is the cost of
  reading a fixed number of nodes, combined with walking the Merkle skip-list.
* **Verifying a proof is _O(log B)_**.  This is the cost of verifying a fixed
  number of fixed-length segments, and verifying a fixed number of _O(log B)_
  shunt proof hashes.
* **Proof size is _O(log B)_**.  A proof has a fixed number of segment proofs,
  where each node has a constant size.  It has _O(log B)_ hashes across all of
  its shunt proofs.

### Consensus Details

The hash function used to generate a path from a key, as well as the hash
function used to generate a node hash, is SHA2-512/256.  This was chosen because
it is extremely fast on 64-bit architectures, and is immune to length extension
attacks.

The hash of an intermediate node is the hash over the following data:

* a 1-byte node ID,
* the sequence of child pointer data (dependent on the type of node),
* the 1-byte length of the path prefix this node contains,
* the 0-to-32-byte path prefix

A single child pointer contains:
* a 1-byte node ID,
* a 1-byte path character,
* the 32-byte block header hash of the pointed-to block

A `node4`, `node16`, `node48`, and `node256` each have an array of 4,
16, 48, and 256 child pointers each.

Children are listed in a `node4`, `node16`, and `node48`'s child pointer arrays in the
order in which they are inserted.  While searching for a child in a `node4` or
`node16` requires a linear scan of the child pointer array, searching a `node48` is done 
by looking up the child's index in its child pointer array using the
path character byte as an index into the `node48`'s 256-byte child pointer
index, and then using _that_ index to look up the child pointer.  Children are
inserted into the child pointer array of a `node256` by using the 1-byte
path character as the index.

The disk pointer stored in a child pointer, as well as the storage mechanism for
mapping hashes of values (leaves in the MARF) to the values themselves, are both
unspecified by the consensus rules.  Any mechanism or representation is
permitted.

## Implementation

The implementation is in Rust, and is about 4,400 lines of code.  It stores each
ART in a separate file, where each ART file contains the hash of the previous
block's ART's root hash and the locally-defined block identifiers.

The implementation is crash-consistent.  It builds up the ART for block _N_ in
RAM, dumps it to disk, and then `rename(2)`s it into place.

The implementation uses a Sqlite3 database to map values to their hashes.  A
read on a given key will first pass through the ART to find hash(value), and
then query the Sqlite3 database for the value.  Similarly, a write will first
insert hash(value) and value into the Sqlite3 database, and then insert
hash(key) to hash(value) in the MARF.

## References

[1] https://db.in.tum.de/~leis/papers/ART.pdf
