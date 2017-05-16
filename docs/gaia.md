Gaia: The Blockstack Storage System
====================================

The Blockstack storage system, called "Gaia", is used to host each user's data
without requiring users to run their own servers.

Gaia works by hosting data in one or more existing storage systems of the user's choice.
These storage systems include cloud storage systems like Dropbox and Google
Drive, they include personal servers like an SFTP server or a WebDAV server, and
they include decentralized storage systems like BitTorrent or IPFS.  The point
is, the user gets to choose where their data lives, and Gaia enables
applications to access it via a uniform API.

A high-level analogy is to compare Gaia to the VFS and block layer in a UNIX
operating system kernel, and to compare existing storage systems to block
devices.  Gaia has "drivers" for each storage system that allow it to load,
store, and delete chunks of data via a uniform interface, and it gives
applications a familiar API for organizing their data.

Applications interface with Gaia via the [Blockstack Core
API](https://github.com/blockstack/blockstack-core/tree/master/api).  Javascript
applications connect to Gaia using [Blockstack Portal](https://github.com/blockstack/blockstack-portal),
which helps them bootstrap a secure connection to Blockstack Core.

# Datastores

Gaia organizes data into datastores.  A **datastore** is a filesystem-like
collection of data that is backed by one or more existing storage systems.

When a user logs into an application, the application will create or connect to
the datastore that holds the user's data.  Once connected, it can proceed to
interact with its data via POSIX-like functions: `mkdir`, `listdir`, `rmdir`,
`getFile`, `putFile`, `deleteFile`, and `stat`.

A datastore has exactly one writer: the user that creates it.  However, all data
within a datastore is world-readable by default, so other users can see the
owner's writes even when the owner is offline.  Users manage access controls
by encrypting files and directories to make them readable to other specific users.
All data in a datastore is signed by a datastore-specific key on write, in order
to guarantee that readers only consume authentic data.

The application client handles all of the encryption and signing.  The other
participants---Blockstack Portal, Blockstack Core, and the storage
systems---only ferry data back and forth between application clients.

## Data Organization

True to its filesystem inspiration, data in a datastore is organized into a
collection of inodes.  Each inode has two parts:

* a **header**, which contains:

   * the inode type (i.e. file or directory)

   * the inode ID (i.e. a UUID4)

   * the hash of the data it stores

   * the size of the data it stores

   * a signature from the user

   * the version number

   * the ID of the device from which it was sent (see Advanced Topics below)

* a **payload**, which contains the raw bytes to be stored.

   * For files, this is just the raw bytes.

   * For directories, this is a serialized data structure that lists the names
     and inode IDs of its children, as well as a copy of the header.

The header has a fixed length, and is somewhat small--only a few hundred bytes.
The payload can be arbitrarily large.

## Data Consistency

The reason for organizing data this way is to make cross-storage system reads
efficient, even when there are stale copies of the data available.  In this
organization, reading an inode's data is a matter of:

1. Fetching all copies of the header

2. Selecting the header with the highest version number

3. Fetching the payload from the storage system that served the latest header.

This way, we can guarantee that:

* The inode payload is fetched *once* in the common case, even if there are multiple stale copies of the inode available.

* All clients observe the *strongest* consistency model offerred by the
  underlying storage providers.

* All readers observe a *minimum* consistency of monotonically-increasing reads.

* Writers observe sequential consistency.

This allows Gaia to interface with decentralized storage systems that make
no guarantees regarding data consistency.

*(Aside 1: The Core node keeps track of the highest last-seen inode version number,
so if all inodes are stale, then no data will be returned).*

*(Aside 2: In step 3, an error path exists whereby all storage systems will be
queried for the payload if the storage system that served the fresh inode does
not have a fresh payload).*

# Accessing the Datastore

Blockstack applications get access to the datastore as part of the sign-in
process.  Suppose the user wishes to sign into the application `foo.app`.  Then,
the following protocol is executed:

![Gaia authentication](/docs/figures/gaia-authentication.png)

1. Using `blockstack.js`, the application authenticates to Blockstack Portal via
`makeAuthRequest()` and `redirectUserToSignIn()`.

2. When Portal receives the request, it contacts the user's Core node to get the
   list of names owned by the user.

3. Portal redirects the user to a login screen, and presents the user with the
   list of names to use.  The user selects which name to sign in as.

4. Now that Portal knows which name to use, and which application is signing in,
   it loads the datastore private key and requests a Blockstack Core session
token.  This token will be used by the application to access Gaia.

5. Portal creates an authentication response with `makeAuthResponse()`, which it
   relays back to the application.

6. The application retrieves the datastore private key and the Core session
   token from the authentication response object.


## Creating a Datastore

Once the application has a Core session token and the datastore private key, it
can proceed to connect to it, or create it if it doesn't exist.  To do so, the
application calls `datastoreConnectOrCreate()`.

This method contacts the Core node directly.  It first requests the public
datastore record, if it exists.  The public datastore record
contains information like who owns the datastore, when it was created, and which
drivers should be used to load and store its data.

![Gaia connect](/docs/figures/gaia-connect.png)

Suppose the user signing into `foo.app` does not yet have a datastore, and wants
to store her data on storage providers `A`, `B`, and `C`.  Then, the following
protocol executes:

1.  The `datastoreConnectOrCreate()` method will generate a signed datastore record
stating that `alice.id`'s public key owns the datastore, and that the drivers
for `A`, `B`, and `C` should be loaded to access its data.

2.  The `datastoreConnectOrCreate()` method will call `mkdir()` to create a
signed root directory.

3.  The `datastoreConnectOrCreate()` method will send these signed records to the Core node.
The Core node replicates the root directory header (blue path), the root
direcory payload (green path), and the datastore record (gold path).

4.  The Core node then replicates them with drivers `A`, `B`, and `C`.

Now, storage systems `A`, `B`, and `C` each hold a copy of the datastore record
and its root directory.

*(Aside: The datastore record's consistency is preserved the same way as the
inode consistency).*

## Reading Data

Once the application has a Core session token, a datastore private key, and a
datastore connection object, it can proceed to read it.  The available methods
are:

* `listDir()`:  Get the contents of a directory

* `getFile()`:  Get the contents of a file

* `stat()`:  Get a file or directory's header

Reading data is done by path, just as it is in UNIX.  At a high-level, reading
data involes (1) resolving the path to the inode, and (2) reading the inode's
contents.

Path resolution works as it does in UNIX: the root directory is fetched, then
the first directory in the path, then the second directory, then the third
directory, etc., until either the file or directory at the end of the path is
fetched, or the name does not exist.

### Authenticating Data

Data authentication happens in the Core node,.
This is meant to enable linking files and directories to legacy Web
applications.  For example, a user might upload a photo to a datastore, and 
create a public URL to it to share with friends who do not yet use Blockstack.

By default, the Core node serves back the inode payload data
(`application/octet-stream` for files, and `application/json` for directories).
The application client may additionally request the signatures from the Core
node if it wants to authenticate the data itself.

### Path Resolution

Applications do not need to do path resolution themselves; they simply ask the
Blockstack Core node to do so on their behalf.  Fetching the root directory
works as follows:

1. Get the root inode ID from the datastore record.

2. Fetch all root inode headers.

3. Select the latest inode header, and then fetch its payload.

4. Authenticate the data.

For example, if a client wanted to read the root directory, it would call
`listDir()` with `"/"` as the path.

![Gaia listdir](/docs/figures/gaia-listdir.png)

The blue paths are the Core node fetching the root inode's headers.  The green
paths are the Core node selecting the latest header and fetching the root
payload.  The Core node would reply the list of inode names within the root
directory.

Once the root directory is resolved, the client simply walks down the path to
the requested file or directory.  This involves iteratively fetching a
directory, searching its children for the next directory in the path, and if it
is found, proceeding to fetch it.

### Fetching Data

Once the Core node has resolved the path to the base name, it looks up the inode
ID from the parent directory and fetches it from the backend storage providers
via the relevant drivers.

For example, fetching the file `/bar` works as follows:

![Gaia getFile](/docs/figures/gaia-getfile.png)

1. Resolve the root directory (blue paths)

2. Find `bar` in the root directory

3. Get `bar`'s headers (green paths)

4. Find the latest header for `bar`, and fetch its payload (gold paths)

5. Return the contents of `bar`.

## Writing Data

There are three steps to writing data:

* Resolving the path to the inode's parent directory

* Creating and replicating the new inode

* Linking the new inode to the parent directory, and uploading the new parent
  directory.

All of these are done with both `putFile()` and `mkdir()`.

### Creating a New Inode

When it calls either `putFile()` or `mkdir()`, the application client will
generate a new inode header and payload and sign them with the datastore private
key.  Once it has done so successfully, it will insert the new inode's name and
ID into the parent directory, give the parent directory a new version number,
and sign and replicate it and its header.

For example, suppose the client attempts to write the data `"hello world"` to `/bar`.
To do so:

![Gaia putFile](/docs/figures/gaia-putfile.png)

1. The client executes `listDir()` on the parent directory, `/` (blue paths).

2. If an inode by the name of `bar` exists in `/`, then the method fails.

3. The client makes a new inode header and payload for `bar` and signs them with
   the datastore private key.  It replicates them to the datastore's storage
drivers (green paths).

4. The client adds a record for `bar` in `/`'s data obtained from (1),
   increments the version for `/`, and signs and replicates `/`'s header and
payload (gold paths).


### Updating a File or Directory

A client can call `putFile()` multiple times to set the file's contents.  In
this case, the client creates, signs, and replicates a new inode header and new
inode payload for the file.  It does not touch the parent directory at all.
In this case, `putFile()` will only succeed if the parent directory lists an
inode with the given name.

A client cannot directly update the contents of a directory.

## Deleting Data

Deleting data can be done with either `rmdir()` (to remove an empty directory)
or `deleteFile()` (to remove a file).  In either case, the protocol executed is

1. The client executes `listDir()` on the parent directory

2. If an inode by the given name does not exist, then the method fails.

3. The client removes the inode's name and ID from the directory listing, signs
   the new directory, and replicates it to the Blockstack Core node.

4. The client tells the Blockstack Core node to delete the inode's header and
   payload from all storage systems.


# Advanced Topics

These features are still being implemented.

## Data Integrity 

What happens if the client crashes while replicating new inode state?  What
happens if the client crashes while deleting inode state?  The data hosted in
the underlying data stores can become inconsistent with the directory structure.

Given the choice between leaking data and rendering data unresolvable, Gaia
chooses to leak data.

### Partial Inode-creation Failures

When creating a file or directory, Gaia stores four records in this order:

* the new inode payload

* the new inode header

* the updated parent directory payload

* the updated parent directory header

If the new payload replicates successfully but the new header does not, then the
new payload is leaked.

If the new payload and new header replicate successfully, but neither parent
directory record succeeds, then the new inode header and payload are leaked.

If the new payload, new header, and updated parent directory payload replicate
successfully, but the updated parent header fails, then not only are the new
inode header and payload leaked, but also *reading the parent directory will
fail due to a hash mismatch between its header and inode*.  This can be detected
and resolved by observing that the copy of the header in the parent directory
payload has a later version than the parent directory header indicates.

### Partial Inode-deletion Failures

When deleting a file or directory, Gaia alters records in this order:

* update parent directory payload

* update parent directory header

* delete inode header

* delete inode payload 

Similar to partial failures from updating parent directories when creating
files, if the client replicates the new parent directory inode payload but fails
before it can update the header, then clients will detect on the next read that
the updated payload is valid because it has a signed inode header with a newer
version.

If the client successfully updates the parent directory but fails to delete
either the inode header or payload, then they are leaked.  However, since the
directory was updated, no correct client will access the deleted inode data.

### Leak Recovery

Gaia's storage drivers are designed to keep the inode data they store in a
"self-contained" way (i.e. within a single folder or bucket).  In the future,
we will implement a `fsck`-like tool that will scan through a datastore and find
the set of inode headers and payloads that are no longer referenced and delete
them.

## Multi-Device Support

Contemporary users read and write data across multiple devices.  In this
document, we have thus far described datastores with the assumption that there
is a single writer at all times.

This assumption is still true in a multi-device setting, since a user is
unlikely to be writing data with the same application simultaneously from two
different devices.

However, an open question is how multiple devices can access the same
application data for a user.  Our design goal is to **give each device its own
keyring**, so if it gets lost, the user can revoke its access without having to
re-key her other devices.

To do so, we'll expand the definition of a datastore to be a **per-user,
per-application, and per-device** collection of data.  The view of a user's
application data will be constructed by merging each device-specific
datastore, and resolving conflicts by showing the "last-written" inode (where
"last-written" is determined by a loosely-synchronized clock).

For example, if a user uploads a profile picture from their phone, and then
uploads a profile picture from their tablet, a subsequent read will query the
phone-originated picture and the tablet-originated picture, and return the
tablet-originated picture.

The aforementioned protocols will need to be extended to search for inode
headers not only on each storage provider, but also search for inodes on the
same storage provider that may have been written by each of the user's devices.
Without careful optimization, this can lead to a lot of inode header queries,
which we address in the next topic.

## A `.storage` Namespace

Blockstack Core nodes can already serve as storage "gateways".  That is, one
node can ask another node to store its data and serve it back to any reader.

For example, Alice can make her Blockstack Core node public and program it to
store data to her Amazon S3 bucket and her Dropbox account.  Bob can then post data to Alice's 
node, causing her node to replicate data to both providers.  Later, Charlie can
read Bob's data from Alice's node, causing Alice's node to fetch and serve back
the data from her cloud storage.  Neither Bob nor Charlie have to set up accounts on
Amazon S3 and Dropbox this way.

Since Alice is on the read/write path between Bob and Charlie and cloud storage,
she has the opportunity to make optimizations.  First, she can program her
Core node to synchronously write data to
local disk and asynchronously back it up to S3 and Dropbox.  This would speed up
Bob's writes, but at the cost of durability (i.e. Alice's node could crash
before replicating to the cloud).

In addition, Alice can program her Core node to service all reads from disk.  This
would speed up Charlie's reads, since he'll get the latest data without having
to hit back-end cloud storage providers.

Since Alice is providing a service to Bob and Charlie, she will want
compensation.  This can be achieved by having both of them send her money via
the underlying blockchain.

To do so, she would register her node's IP address in a
`.storage` namespace in Blockstack, and post her rates per GB in her node's
profile and her payment address.  Once Bob and Charlie sent her payment, her
node would begin accepting reads and writes from them up to the capacity
purchased.  They would continue sending payments as long as Alice provides them
with service.

Other experienced node operators would register their nodes in `.storage`, and
compete for users by offerring better durability, availability, performance,
extra storage features, and so on.
