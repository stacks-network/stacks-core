### How is this different from Namecoin?

The implementation that uses the Bitcoin blockchain is different from Namecoin in two fundamental ways 1) it uses the same blockchain as Bitcoin instead of being on a different blockchain (Bitcoin's blockchain is the most secure in terms of hashpower), and 2) it stores the data outside of the blockchain in a DHT to avoid bloating of the blockchain (unlike Namecoin which stores all data in the Namecoin blockchain). There are also other differences e.g., how pricing works for registrations, and how the money for registrations/updates actually goes to Bitcoin miners (instead of burning/wasting money).

### Is there a mechanism to store encrypted data?

Not in this software. Simply encrypt your file, then submit that data.

### Can't someone just store huge files in the DHT?

Currently, yes. We plan to limit the size of key-value pairs in a future release. The DHT is not meant for storage of large files e.g., pictures, videos etc and is meant for basic profile information and for discovery of other services (e.g., a private data store). 

### Aren't DHTs vulnerable to sybil attacks?

Yes. Unfortunately like Bitcoin and other systems, sybil attacks are possible. There is no theretical solution to sybil attacks, but we can take certain practical steps to minimize the effects and risks of this. Also, keep in mind that the only type of attack possible on the DHT is the "data unavailablity" attack. Anyone can independently verify that they received the correct data by checking the hash of the data in the blockchain. 

### Can nodes just pop in and out and confuse the network?

Yes, with nodes coming and going (churn) in a DHT the routing tables of the DHT can get affected. The DHT netowrk will recover from this over time, so unless someone is actively attacking the DHT 24/7 occasional churn is going to be largely unnoticaable for most practical purposes.  

### Is there any incentive to run a node?

Not currently, no. Only that anyone running opennamed is also by default running a full DHT node, so more users should result in more DHT nodes. If you have any ideas about explicit incentives for running DHT nodes, feel free to reach out!

### Is there a layer on top of the DHT that can make it simple to grab the data?

Anyone can create a cache of all the DHT data (by using the index of the data from the blockchain). We plan on creating such caches (e.g., in memcached servers) and providing easy access to the data through an API. Remember that anyone can verify that the data they received is correct by checking the hash of the data in the blockchain (so you're not trusting the DHT or the cache server). 

### Can I build and host my own index/cache of the data in the DHT?

Absolutely! Anyone can. See above. 