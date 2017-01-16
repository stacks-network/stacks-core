# Basic Usage

This section describes the basic features of Blockstack CLI.  This document is meant to supplement the built-in documentation in the tool.

If at any point you forget how to use a particular CLI command, you can just type `blockstack <NAME OF COMMAND>`, and you will be interactively prompted for each piece of data it needs.

## Client Setup

By default, the CLI tool will automatically configure itself with sensible defaults.  If you don't like the defaults, you can change them by running `blockstack configure`.

In particular, you can enable the advanced features with `blockstack set_advanced_mode on`.  Please see the `advanced_usage.md` file for details.

## Wallet Setup

Blockstack uses its own wallet, stored to `~/.blockstack/wallet.json`.  You do not need a wallet to do lookups.

Blockstack will set up a wallet for you when you try to do something that requires payment (e.g. registering a name).  When prompted, you will be asked for a wallet password.  This password will be used to encrypt your private keys, and must be at least 16 characters.  We recommend using a random string of words that you can easily memorize, since **there is no way to recover your wallet if you forget your password.**

Once you generate a wallet, **make a back-up to a USB key**.  You can also print it out, since it's just a string of plain text.

## Doing Lookups

There are two kinds of lookups:  a `whois` and a `lookup`.  The `whois` queries only information found in the blockchain, whereas a `lookup` queries off-chain data.

A `lookup` fetches the off-chain profile and zonefile.  For example:

```
   $ blockstack lookup guylepage3.id
   {
       "profile": {
           "@type": "Person", 
           "account": [
               {
                   "@type": "Account", 
                   "identifier": "1Mp5vKwCbekeWetMHLKDD2fDLJzw4vKxiQ", 
                   "role": "payment", 
                   "service": "bitcoin"
               }, 
               {
                   "@type": "Account", 
                   "identifier": "guylepage3", 
                   "proofType": "http", 
                   "proofUrl": "https://twitter.com/guylepage3/status/731252874886385665", 
                   "service": "twitter"
               }, 
               {
                   "@type": "Account", 
                   "identifier": "g3lepage", 
                   "proofType": "http", 
                   "proofUrl": "https://www.facebook.com/g3lepage/posts/10154223148908760", 
                   "service": "facebook"
               }, 
               {
                   "@type": "Account", 
                   "identifier": "guylepage3", 
                   "proofType": "http", 
                   "proofUrl": "https://gist.github.com/guylepage3/06f522444fb71f1daf01a534396d1f9e", 
                   "service": "github"
               }
           ], 
           "address": {
               "@type": "PostalAddress", 
               "addressLocality": "New York, NY"
           }, 
           "description": "@blockstackorg developer. 1st hire, Design Partner @blockstacklabs (YC/USV backed) entrepreneur, blockchain, creative, marketing, surf, triathlon, ironman", 
           "graph": {
               "url": "https://s3.amazonaws.com/grph/guylepage3"
           }, 
           "image": [
               {
                   "@type": "ImageObject", 
                   "contentUrl": "https://s3.amazonaws.com/dx3/guylepage3", 
                   "name": "cover"
               }, 
               {
                   "@type": "ImageObject", 
                   "contentUrl": "https://s3.amazonaws.com/kd4/guylepage3", 
                   "name": "avatar"
               }
           ], 
           "name": "Guy Lepage", 
           "website": [
               {
                   "@type": "WebSite", 
                   "url": "http://blockstack.com/team"
               }
           ]
       }, 
       "zonefile": {
           "$origin": "guylepage3.id", 
           "$ttl": 3600, 
           "uri": [
               {
                   "name": "_http._tcp", 
                   "priority": 10, 
                   "target": "https://blockstack.s3.amazonaws.com/guylepage3.id", 
                   "weight": 1
               }
           ]
       }
    }
```
There will always be two keys defined: `profile` and `zonefile`.  The hash of the contents of the `zonefile` object are stored in the blockchain, and the Blockstack servers hold copies of zonefile data.  The `profile` object is constructed from a **signed JSON web token** (JWT), which is hosted on the storage providers of the user's choice (as determined in the `client.ini` config file).  A modern zonefile points to where the profile JWT is hosted.

The `whois` query is more low-level, and pulls up information that's hosted only in the blockchain.  Here's a sample `whois` query:
```
    $ blockstack whois muneeb.id
    {
       "approx_expiration_date": "2016 Sep 09 13:12:31 UTC", 
       "block_preordered_at": 373821, 
       "block_renewed_at": 373821, 
       "expire_block": 426416, 
       "has_zonefile": true, 
       "last_transaction_height": 402804, 
       "last_transaction_id": "904c5f187ab143d187e26afaddaa6061059451407193fbfc4c4a9b0baa24dbd7", 
       "owner_address": "1QJQxDas5JhdiXhEbNS14iNjr8auFT96GP", 
       "owner_script": "76a914ff95f5612a26a81e919e4b6e63fdd929fd115d6d88ac", 
       "zonefile_hash": "3085137b19ce56092f5cb91b7f78d073c815dbc1"
    }
```

This information includes the block heights at which the name was preordered (for the first time ever), when it was registered to its curent owner, when it will expire, and when the last transaction (whose ID is given) that affected the name was seen.  It also encodes the hash of the zonefile (stored off-chain), the owner's address (public key hash), and owner script (scriptPubKey from Bitcoin).

Note that the `approx_expiration_data` is *approxmiate*.  The system uses the `expire_block` to determine when exactly the name expires; the date is extrapolated from the average block time.  You should renew your name well before it expires, just to be sure the transaction gets accepted.  We recommend doing it 1,000 blocks before it is set to expire.

### A Note on Legacy Profiles

Older profiles used a different structure for storing information.  Looking them up will produce a "legacy" zonefile, as well as the profile it represents.

Legacy zonefiles do not look like DNS zonefiles at all.  For example:
```
    $ blockstack lookup muneeb.id
    {
       "profile": {
           "@type": "Person", 
           "account": [
               {
                   "@type": "Account", 
                   "identifier": "muneeb", 
                   "proofType": "http", 
                   "service": "twitter"
               }, 
               {
                   "@type": "Account", 
                   "identifier": "muneeb.ali", 
                   "proofType": "http", 
                   "service": "facebook"
               }, 
               {
                   "@type": "Account", 
                   "identifier": "muneeb-ali", 
                   "proofType": "http", 
                   "service": "github"
               }, 
               {
                   "@type": "Account", 
                   "identifier": "1LNLCwtigWAvLkNakUK4jnmmvdVvmULeES", 
                   "role": "payment", 
                   "service": "bitcoin"
               }, 
               {
                   "@type": "Account", 
                   "contentUrl": "http://muneebali.com/static/files/key.asc", 
                   "identifier": "9862A3FB338BE9EB6C6A5E05639C89272AFEC540", 
                   "role": "key", 
                   "service": "pgp"
               }
           ], 
           "address": {
               "@type": "PostalAddress", 
               "addressLocality": "New York, NY"
           }, 
           "description": "Co-founder of Onename (YC S14), final-year PhD candidate at Princeton. Interested in distributed systems and blockchains.", 
           "image": [
               {
                   "@type": "ImageObject", 
                   "contentUrl": "https://s3.amazonaws.com/kd4/muneeb", 
                   "name": "avatar"
               }, 
               {
                   "@type": "ImageObject", 
                   "contentUrl": "https://s3.amazonaws.com/dx3/muneeb", 
                   "name": "cover"
               }
           ], 
           "name": "Muneeb Ali", 
           "website": [
               {
                   "@type": "WebSite", 
                   "url": "http://muneebali.com"
               }
           ]
       }, 
       "zonefile": {
           "avatar": {
               "url": "https://s3.amazonaws.com/kd4/muneeb"
           }, 
           "bio": "Co-founder of Onename (YC S14), final-year PhD candidate at Princeton. Interested in distributed systems and blockchains.", 
           "bitcoin": {
               "address": "1LNLCwtigWAvLkNakUK4jnmmvdVvmULeES"
           }, 
           "cover": {
               "url": "https://s3.amazonaws.com/dx3/muneeb"
           }, 
           "facebook": {
               "proof": {
                   "url": "https://facebook.com/muneeb.ali/posts/10152524743274123"
               }, 
               "username": "muneeb.ali"
           }, 
           "github": {
               "proof": {
                   "url": "https://gist.github.com/muneeb-ali/0f00d4da967646ee0bc3"
               }, 
               "username": "muneeb-ali"
           }, 
           "graph": {
               "followee_count": 4, 
               "url": "https://s3.amazonaws.com/grph/muneeb"
           }, 
           "location": {
               "formatted": "New York, NY"
           }, 
           "name": {
               "formatted": "Muneeb Ali"
           }, 
           "pgp": {
               "fingerprint": "9862A3FB338BE9EB6C6A5E05639C89272AFEC540", 
               "url": "http://muneebali.com/static/files/key.asc"
           }, 
           "twitter": {
               "proof": {
                   "url": "https://twitter.com/muneeb/status/483765788478689280"
               }, 
               "username": "muneeb"
           }, 
           "v": "0.2", 
           "website": "http://muneebali.com"
       }
    }
```

## Blockstack Wallet

The Blockstack wallet has three keys: your payment key, your ownership key (i.e. the key that owns the names), and your data key (i.e. the key that signs your profile data).
In the basic mode of operation, you can query information about them with these commands:

* `blockstack balance`:  Query your payment account balance (excludes transactions with less than 6 confirmations).
* `blockstack deposit`:  Get your payment address information.  This is the address that **pays for names and transaction fees**.
* `blockstack import`:  Get your name owner address.  This is the address for **transferring a name to a different wallet**.
* `blockstack names`:  See the list of names that are owned by your owner address.

## Registering a Name

To register a name, simply type:
```
    $ blockstack register <YOUR NAME>.id
```

At this time, the name must end in `.id`. It will be registered in the `.id` namespace, since only the `.id` namespace exists (see [here](https://blockstack.org/docs/namespaces) for details).

You will be prompted to confirm the purchase, and (if you haven't entered it yet), you will be prompted for your wallet password.

If you'd like to see the price of a name, without actually purchasing it, you can use `blockstack price <YOUR NAME>.id`.

### A Note on Transaction Fees
The total name cost includes all the relevant transaction fees.  However, fee prices are dynamic, and may change during the registration (which requires issuing three transactions).

To ensure timely registration, you should fill your payment address with **at least +0.001 BTC more than the name cost**.

## Migrating an Existing Name to the New Profile Schema

Some advanced options are disabled for older names registered through [Onename](https://onename.com).  To enable them, you will need to migrate your name's off-chain data.

To do so, run `blockstack migrate <YOUR NAME>.id`.  It will take about an hour and a half to complete, but only needs to be done once, and only if your name has a legacy zonefile (see above).

## Checking the Blockstack Server

You can track the progress of your name transactions with `blockstack info`, which will show you which names have unconfirmed transactions (and what kind they are).  The CLI waits for 10 confirmations before considering it confirmed.

When registering a name, a name will pass through three states: `preorder`, `register`, and `update`.  The first step registers your public key and the hash of the name, and waits for it to be confirmed (so no one can front-run you when you reveal the name).  The second step reveals the name in the blockchain; you can look at the transaction in a block explorer and find it in the `OP_RETURN` data.  The third stage sets up your zonefile and your profile, and writes your zonefile's hash to the blockchain.

## Other Operations

### Transferring a Name

You can send a name to a new ownership address with `blockstack transfer <YOUR NAME>.id <NEW ADDRESS>`.

### Renewing a Name

Names do not last forever, and must be periodically renewed.  You can see when a name expires using `whois`, and renew it with `blockstack renew <YOUR NAME>.id`.

**If you do not renew your name, someone else can register it, and you will not be able to get it back.**  The best alternative is to try to ask the new owner if (s)he will sell it back to you.

### Revoking a Name

If you lose your Blockstack wallet or the device(s) that host it, you have the option of revoking the name using a backed up copy of your wallet.  To do so, type `blockstack revoke <YOUR NAME>.id`.


### Updating a Name's Zonefile

**OpenBazaar Users**:  If you are trying to add your OpenBazaar GUID to your Blockstack ID, please follow [these instructions](https://github.com/blockstack/blockstack-cli/blob/master/docs/openbazaar.md) instead.

**CAUTION**: You almost never want to update your name's zonefile, since it's slow, tedious, and costs money.  It is meant primarily for recovering from zonefile loss, for changing where people find your profile, and for changing your data public key.  If you want to store data in your profile, please see the [data storage](https://github.com/blockstack/blockstack-cli/blob/master/docs/advanced_usage.md#data-storage) and [accounts](https://github.com/blockstack/blockstack-cli/blob/master/docs/advanced_usage.md#accounts) commands in the [advanced usage](https://github.com/blockstack/blockstack-cli/blob/master/docs/advanced_usage.md) section (but read the [warnings](https://github.com/blockstack/blockstack-cli/blob/master/docs/advanced_usage.md#a-word-of-warning) first).

If you want to change the name's zonefile, you can do so with `blockstack update`.  You must specify the new zonefile to do so.  For example:

```
    $ blockstack update judecn.id '$ORIGIN judecn.id
    > $TTL 3600
    > pubkey TXT "pubkey:data:04cabba0b5b9a871dbaa11c044066e281c5feb57243c7d2a452f06a0d708613a46ced59f9f806e601b3353931d1e4a98d7040127f31016311050bedc0d4f1f62ff"
    > _file URI 10 1 "file:///home/jude/.blockstack/storage-disk/mutable/judecn.id"
    > _https._tcp URI 10 1 "https://blockstack.s3.amazonaws.com/judecn.id"
    > _http._tcp URI 10 1 "http://node.blockstack.org:6264/RPC2#judecn.id"
    > _dht._udp URI 10 1 "dht+udp://fc4d9c1481a6349fe99f0e3dd7261d67b23dadc5"
    > '
```

The zonefile can be any valid DNS zonefile, but must follow these extra rules:
* There must be only one `$ORIGIN`, and it must be the blockstack ID.
* There must be at least one `URI` resource record.
* If you want to set a new data keypair, you must do so via a `TXT` record named `pubkey`, and the text field must start with `pubkey:data:` (as per the example).  It must be an ECDSA public key.

**WARNING**:  Each of the URLs must refer to the **signed JSON Web Token** (JWT) that encodes your profile data.  The JWT can be signed either with the private key that owns your name, or with a private key that matches the `pubkey:data:` TXT record.  If you do not do this, your profile **will not be readable** to the Blockstack CLI tool or to any public profile resolvers.
