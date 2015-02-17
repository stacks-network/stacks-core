# Blockstore Design

__Table of Contents__

- [Design Overview](<#overview>)
- [Design Decisions](<#decisions>)
    - [Blockchain](#blockchain)
    - [Data Storage](#data-storage)
    - [Registration Fees](#registration-fees)
    - [End-to-end Design Principle](#end-to-end-design-principle)
- [Distributed Hash Table](<#dht>)
- [Virtual Blockchain](<#virtual>)
    
## Design Overview
<a name="overview"/>

The following system diagram gives an overview of Blockstore and the sections below give details on each component:

<img src="https://s3.amazonaws.com/onenameblog/openname-bitcoin-dht-diagram-4.png" width="650"/>

## Design Decisions 
<a name="decisions"/>

### Blockchain

Cryptocurrency developers highly value the ability to build on the strongest and best-supported blockchains, and because of this we decided to take a crack at releasing an experimental key-value store on Bitcoin.

### Data Storage 

Storing large amounts of data in the blockchain can lead to blockchain bloat, so we decided to use a DHT for data storage while storing only hashes of the data in the blockchain, yielding virtually unlimited storage.

### Registration Fees 

Miners provide critical infrastructure for the Bitcoin ecosystem and we believe that any services built on top of Bitcoin should contribute to Bitcoin mining incentives.

### End-to-end Design Principle

The end-to-end design principle of keeping the core of the network simple proved to be very successful for the Internet, and we believe this is a good decision for blockchain applications as well. Thus, we use the blockchain for a few basic operations and keeping most of the intelligence client-side.

## Distributed Hash Table 
<a name="dht"/>

The research literature in Distributed Hash Tables (DHTs) is extremeley rich and there are a number of excellent choices available for DHTs. Some of the more popular DHTs include [Chord](http://en.wikipedia.org/wiki/Chord_%28peer-to-peer%29), [Kademlia](http://en.wikipedia.org/wiki/Kademlia), [Pastry](http://en.wikipedia.org/wiki/Pastry_(DHT)) etc. 

## Virtual Blockchain
<a name="virtual"/>
