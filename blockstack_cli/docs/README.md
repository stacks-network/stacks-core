# Documentation

Blockstack CLI is both a command-line interface tool, a system service (daemon), and a Python library for interacting with Blockstack.

## Quick Links

* [Basic command-line usage](https://github.com/blockstack/blockstack-cli/blob/master/docs/basic_usage.md)
* [Advanced command-line usage](https://github.com/blockstack/blockstack-cli/blob/master/docs/advanced_usage.md)
* [Glossary of Terms](https://github.com/blockstack/blockstack-cli/blob/master/docs/glossary.md)
* [How to link your OpenBazaar Store to your Blockstack ID](https://github.com/blockstack/blockstack-cli/blob/master/docs/openbazaar.md)

## Architecture Overview

Most of the complexity of Blockstack lives in its client library.  Specifically, the library does the following:

* Generating and sending name operation transactions.
* Reading, writing, and deleting data in your storage providers (and reading other peoples' data from their storage providers).
* Handling data authenticity, encryption, and validation.
* Querying a Blockstack Server for blockchain-hosted information.

The CLI tool is a wrapper around the library.  Most of its commands are thin wrappers around library functions.

In addition to a CLI tool and library, Blockstack CLI comes with a system service that runs in the background as a daemon.  The daemon does the following:

* Acts as a personal registrar.  It queues up all your name operation transactions, waits for them to be confirmed by the blockchain, sends them out, and replicates your zonefile and profile as needed.
* Hosts your wallet.  Your wallet is never stored in plaintext; it only lives in the daemon's RAM (for when it needs to send out transactions). 
* Allows programmatic access to a subset of CLI commands.  This allows other programs on your computer to do things like look up Blockstack IDs, query their data, and so on.  For security, the daemon will never serve the wallet via the API, nor does it expose any API call that can change data or send transactions (it is effectively a read-only API).

## Files

These files are created by Blockstack CLI:

### Files You Can Edit

These files define how the CLI behaves.

* `~/.blockstack/client.ini`:  This is the CLI config file.  You can interactively modify it with `blockstack configure`.
* `~/.blockstack/wallet.json`:  This is your JSON-encoded wallet.  It contains your password-encrypted keys.

### Files You Can Read

These files are useful primarily for troubleshooting.

* `~/.blockstack/api_endpoint.log`:  This is the log for the system service that manages your wallet, sends your name operations, and accesses your profile and data.  It's a great source for troubleshooting.
* `~/.blockstack/api_endpoint.pid`:  This contains the PID of the system service.
* `~/.blockstack/metadata/`:  This directory contains versioning information for mutable data from other profiles you have read.  It gets used to stop malicious storage providers from serving you older versions of the data you've already seen.
* `~/.blockstack/storage-disk/`:  If you use the `disk` storage driver (it is activated by default), then this is where it holds your zonefiles, profiles, and data.

### Files You Should NOT Edit

You shouldn't touch these files unless you're a developer, and even then, you should only do so at your own risk.

* `~/.blockstack/queues.db`:  This is a SQLite database that contains queued-up transactions for name operations.  If you want to remove any stuck transactions, use `blockstack unqueue` in the [advanced](https://github.com/blockstack/blockstack-cli/blob/master/docs/advanced_usage.md) usage.
* `~/.blockstack/registrar.lock`:  This is a lockfile held by a thread in the registrar thread in the CLI daemon.
* `~/.blockstack/blockchain_headers.dat`:  SPV headers.
* `~/.blockstack/client.uuid`:  Used for anonymous statistics gathering purposes (which you can disable using `blockstack configure`).  If you remove it, a new one will be generated.
