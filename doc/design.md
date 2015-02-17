# Blockstore Design

__Table of Contents__

- [Design Overview](<#design-overview>)
- [Design Decisions](<#design-decisions>)
    - [Blockchain](#blockchain)
    - [Data Storage](#data-storage)
    - [Registration Fees](#registration-fees)
    - [End-to-end Design Principle](#end-to-end-design-principle)
- [Distributed Hash Table](<#distributed-hash-table>)
- [Virtual Blockchain](<#virtual-blockchain>)
    
## Design Overview

The following system diagram gives an overview of Blockstore and the sections below give details on each component:

<img src="https://s3.amazonaws.com/onenameblog/openname-bitcoin-dht-diagram-4.png" width="650"/>

## Design Decisions 

### Blockchain

Cryptocurrency developers highly value the ability to build on the strongest and best-supported blockchains, and because of this we decided to take a crack at releasing an experimental key-value store on Bitcoin.

There are many different ways of storing data using a blockchain e.g.,  alt-coins (Namecoin, Datacoin), sidechains, and protocols like Counterparty that build embedded chains of consensus on top of the Bitcoin blockchain (let’s call them topchains). The security and reliability of the key-value store directly depends on the reliability and security of the underlying blockchain. Sidechains and topchains have the ability to utilize Bitcoin Core. Building on top of the most secure blockchain is important and currently that happens to be the Bitcoin blockchain.

### Data Storage 

Storing large amounts of data in the blockchain can lead to blockchain bloat, so we decided to use a DHT for data storage while storing only hashes of the data in the blockchain, yielding virtually unlimited storage. The DHT is seamlessly integrated with blockstored.

### Registration Fees 

Miners provide critical infrastructure for the Bitcoin eco-system and it'll be nice if services built on top of Bitcoin can contribute to mining incentives. Therefore, we decided to pay registration fees to miners instead of other methods like burning money.

### End-to-end Design Principle

The [end-to-end design principle](http://en.wikipedia.org/wiki/End-to-end_principle) of keeping the core of the network simple proved to be very successful for the Internet, and we believe this is a good decision for blockchain applications as well. Thus, we use the blockchain for a few basic operations and keeping most of the intelligence client-side.

## Distributed Hash Table 

The research literature in Distributed Hash Tables (DHTs) is extremeley rich and there are a number of excellent choices available for DHTs. Some of the more popular DHTs include [Chord](http://en.wikipedia.org/wiki/Chord_%28peer-to-peer%29), [Kademlia](http://en.wikipedia.org/wiki/Kademlia), [Pastry](http://en.wikipedia.org/wiki/Pastry_(DHT)) etc. We decided to use Kademlia because of a) relative simplicity of the XOR based routing algorithm and the respective analysis, b) accelerated lookups and c) availability of implementations that can be easily integrated with blockstored.

## Virtual Blockchain

We introduce the notion of a virtual blockchain, as operations defined by a higher-layer protocol that are broadcasted in Bitcoin transactions. If you throw away all other data (blocks that have no operations for the higher-layer protocol) and extract the operations, they form a logical chain in a linear fashion just like the underlying blockchain (see figure above). The blockstore protocol is implemented as a virtual blockchain on top of Bitcoin.  
