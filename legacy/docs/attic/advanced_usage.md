# Advanced Usage

This section details some of the advanced features in the CLI.

## A Word of Warning

Advanced features are meant to be used by experienced Blockstack users and developers,  They receive less UI/UX testing than basic features, and their interfaces are expected to change to accomodate bugfixes and security fixes.  Moreover, improper use of some advanced methods can cost you money, corrupt your profile, or compromise your wallet.  Once they receive sufficient testing, an advanced feature may become a basic-mode feature in a subsequent release.

**Do not use advanced mode unless you know what you are doing!**

## Activating Advanced Mode

To activate advanced mode, use the command `blockstack set_advanced_mode on`.

To deactivate it later (recommended), use the command `blockstack set_advanced_mode off`.

## Changing or Using Exiting Keys

If you already have a payment key you want to use, or an owner key you want to migrate over, you can generate a wallet directly with `import_wallet`.  We recommend using this command interactively, so you know which keys correspond to which usages.

## Accounts

With the accounts methods, you can directly manage your social proofs, link existing services to your profile, and store small bits of information.

The account management methods are:
* `get_account`:  Look up an account in a name's profile.  There can be more than one match.
* `list_accounts`:  List all accounts in a name's profile.
* `put_account`:  Add or update an account in a name's profile.
* `delete_account`:  Remove an account from a name's profile.  This may need to be done more than once, if there are duplicates of the account.

## Advanced Blockstack ID Queries

Beyond `lookup` and `whois`, there are a few other more advanced queries you can run on Blockstack IDs.  These include:

### Listing Blockstack IDs
* `get_all_names`:  Get the list of every single Blockstack ID in existance.
* `get_names_owned_by_address`:  Get the list of names owned by a particular ownership address.

### Querying the Blockchain
* `get_name_blockchain_record`:  Get the raw database record for a Blockstack ID.  It will contain a *compressed* history of all name operations that have affected it.  This is meant primarily for debugging purposes; to get an easier-to-parse listing of the information this command returns, use `get_name_blockchain_history`.
* `get_name_blockchain_history`:  Get the set of all prior states a Blockstack ID has been in, keyed by the block heights at which the state-change was processed.
* `get_records_at`:  Get the list of name operation records processed at a particular block height.
* `list_update_history`:  Get the list of all zonefile hashes that a Blockstack ID has ever had.

### Zonefiles
* `get_name_zonefile`:  Get only a Blockstack ID's zonefile.
* `list_zonefile_history`:  Get the list of all zonefiles a Blockstack ID has ever had.  **NOTE:** There is no guarantee that the server will hold copies of old zonefiles. This command is meant mainly for determining which historic zonefiles a server has processed.
* `set_zonefile_hash`:  This is the counterpart to `update`, but instead of setting the zonefile directly and uploading it to storage, you can use this command to directly set the data hash for a Blockstack ID.  **NOTE:** You should ensure that the associated zonefile data has been replicated off-chain to a place where other users can get at it.

### Lightweight Queries

The lightweight lookup protocol for Blockstack is called *Simplified Name Verification* (SNV).  This command returns a prior blockchain-level record given a more recent known-good consensus hash, serial number, or transaction ID of a transaction that contains a consensus hash.  The CLI does not need to trust the Blockstack server to use these commands.

* `lookup_snv`:  Use the Merkle skip-list in the name database to look up a historic name operation on a Blockstack ID.

## Consensus Queries

You can query consensus hash information from the server with the following commands:

* `consensus`:  Get the consensus hash at a particular block height

## Namespace Queries

In addition to querying Blockstack IDs, the CLI has advanced commands for querying namespaces.  These include:

* `get_namespace_blockchain_record`:  Get the raw database record for a Blockstack namespace.  It will contain a *compressed* history of all namespace operations that have affected it.
* `get_names_in_namespace`:  Get the list of every Blockstack ID in a particular namespace.
* `get_namespace_cost`:  Get the cost required to preorder a namespace.  Does *not* include the cost to reveal and ready it, nor does it include the transaction fees.

## Namespace Creation

**WARNING:** We do not recommend that you try to do this by yourself.  Creating a namespace is **EXTREMELY EXPENSIVE**.  If you are interested in creating your own namespace, please contact the Blockstack developers on the [Blockstack Slack](http://chat.blockstack.org).

These methods allow you to create a namespace.  There are three steps:  preordering, revealing, and readying.  Preordering a namespace is like preordering a name--you announce the hash of the namespace ID and the address that will control it.  Revealing a namespace not only reveals the namespace ID, but also sets the pricing and lifetime rules for names in the namespace.  After revealing the namespace, the namespace controller can pre-populate the namespace by importing Blockstack IDs.  Once the namespace has been pre-populated, the controller sends a final transaction that readies the namespace for general use.

* `namespace_preorder`:  Preorder a namespace.
* `namespace_reveal`:  Reveal a namespace, and set its pricing and lifetime parameters.  **NOTE:** This must be done within 144 blocks of sending the namespace preorder transaction.
* `name_import`:  Import a name into a revealed (but not readied) namespace.  You can set its owner address and zonefile hash directly.
* `namespace_ready`:  Open a namespace for general registrations.

## Data Storage

Blockstack allows users to store arbitrary data to any set of storage providers for which the CLI has a driver.  The data will be signed by the user's data key, so when other users read the data later on, they can verify that it is authentic (i.e. the storage provider is not trusted).  Moreover, Blockstack is designed such that users don't have to know or care about which storage providers were used--as far as users can see, storage providers are just shared hard drives.

There are two types of data supported by Blockstack:  *mutable* data, and *immutable* data.  Mutable data is linked by the profile, and can be written as fast and as frequently as the storage provider allows.  Mutable data is addressed by URL.

**WARNING:** While mutable data guarantees end-to-end authenticity, there is a chance that a malicious storage provider can serve new readers stale versions of the data.  That is, users who have read the latest data already will not get tricked into reading stale data, but users who have *not yet* read the latest data *can* be tricked (i.e. the CLI keeps a version number for mutable data to do so).  This must be taken into account if you intend to use this API.

Immutable data, however, is content-addressed, and its cryptographic hash is stored to the user's zonefile.  Writing immutable data will entail updating the zonefile and sending an `update` transaction (handled internally), so it will be slow by comparison.  This has the advantage that storage providers cannot perform the aforementioned stale data attack, but has the downside that writes cost money and take a long time to complete.

That said, we recommend using the mutable data API with several different storage providers whenever possible.

### Mutable Data

The following commands affect mutable data:

* `get_mutable`:  Use the profile to look up and fetch a piece of mutable data.
* `put_mutable`:  Add a link to mutable data to the profile, and replicate the signed data itself to all storage providers.  Other users will need the data's name to read it with `get_mutable`.
* `delete_mutable`:  Remove a link to mutable data from the profile, and ask all storage providers to delete the signed data.

### Immutable Data

The following commnds affect immutable data:

* `get_immutable`:  Look up and fetch a piece of immutable data.  You can supply either the name of the data, or its hash (both are stored in the zonefile, so there is no gain or loss of security in this choice).
* `put_immutable`:  Replicate a piece of data to all storage providers, add its name and hash to the zonefile, and issue an `update` to upload the new zonefile to Blockstack servers and write the hash to the blockchain.
* `delete_immutable`:  Remove the link to the data from the zonefile, ask all storage providers to delete the data, and issue an `update` to upload the new zonefile to Blockstack servers and write the new hash to the blockchain.
* `list_immutable_data_history`:  Given the name of a piece of immutable data, query the zonefile history to find the historic list of hashes it has had.  **NOTE:** Like `list_zonefile_history` above, this only returns data hashes for the data if the Blockstack server has the historic zonefile.

## Fault Recovery

Sometimes, things beyond our control can happen.  Transactions can get stuck, storage providers can go offline or corrupt data, and so on.  These commands are meant to assist in recovering from these problems:

* `set_profile`:  Directly set a Blockstack ID's profile.  All previous accounts, data links, etc. must be included in the new profile, since the old profile (if still present) will be overwritten by the one given here.
* `convert_legacy_profile`:  Given a legacy profile taken from a resolver, directly convert it into a new profile.  This can be used with `set_profile` to recover from a failed profile migration.
* `unqueue`:  If a transaction gets lost or stuck, you can remove it from the CLI's transaction queue with this command.  This will allow you to re-try it.
* `rpcctl`:  This lets you directly start or stop the Blockstack CLI's background daemon, which lets you recover from any crashes it experiences (you can find a trace of its behavior in `~/.blockstack/api_endpoint.log`)

## Programmatic Access

Other programs may want to make RPC calls the Blockstack CLI daemon.  They can do so using either the `blockstack_client` Python package, or they can do so via the CLI as follows:

* `rpc`:  Issue a JSON RPC call.  Takes a raw JSON string that encodes a list of arguments.

