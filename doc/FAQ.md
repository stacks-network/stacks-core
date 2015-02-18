#### Why did you choose to build on top of Bitcoin?

Bitcoin is the blockchain with the most users, the largest market cap, the most amount of software available for it, and the highest amount of security (in terms of the cost of attack). It only makes sense to gravitate to the top blockchain among cryptocurrencies.

#### Are you open to building on other blockchains?

Yes! While we decided to follow our instincts and build our experimental KV store on the Bitcoin blockchain, we are and have been considering other options like alt-coins, sidechains, and even a Namecoin upgrade. If you have a suggestion and some detailed information about why it makes more sense, please open an issue and we'll discuss.

#### How is the Blockstore different from Namecoin?

This is different from Namecoin in a few fundamental ways:

1. It uses the Bitcoin blockchain, which is the top blockchain. See above.
2. Rather than store data directly in the Blockchain, this stores the data outside of the blockchain in a DHT. This reduces blockchain bloat and allows for more data to be conveniently stored.
3. Each namespace has a different pricing scheme for names. That means you can use a namespace with expensive names in order to avoid squatting (ideal for domains), or you can use a namespace with names that cost almost nothing, in order to save money (ideal for non-fungible tokens like trading cards), or you can go for something in the middle (ideal for usernames).
4. Fees paid to register names go to miners instead of being burned or essentially wasted. This incentivizes mining and increases the overall security of the network.

#### Is there a mechanism to store encrypted data?

There isn't any support for this in this repo. However, to store encrypted data, simply encrypt your file before submitting the data to the blockchain.

#### Can't someone just store huge files in the DHT?

Currently, yes. We plan to limit the size of key-value pairs in a future release. The DHT is not meant for storage of large files (e.g. pictures, videos, etc.) and is only intended for relatively small or moderately sized plaintext files.

#### Aren't DHTs vulnerable to sybil attacks?

Yes. Unfortunately like Bitcoin and other systems, sybil attacks are possible. There is no theretical solution to sybil attacks, but we can take certain practical steps to minimize the effects and risks of this. Also, keep in mind that the only type of attack possible on the DHT is the "data unavailablity" attack. Anyone can independently verify that they received the correct data by checking the hash of the data in the blockchain. 

#### Can nodes just pop in and out and confuse the network?

Yes, with nodes entering and exiting a DHT (a process known as churn), the routing tables of the DHT can get affected. The DHT network will recover from this over time, so unless someone is actively attacking the DHT 24/7, occasional churn is going to be largely unnoticeable.

#### Is there any incentive to run a node?

Not currently, no. Only that anyone running blockstored is also by default running a full DHT node, so more users should result in more DHT nodes. If you have any ideas about explicit incentives for running DHT nodes, feel free to reach out!

#### Is there a layer on top of the DHT that can make it simpler to grab the data?

Anyone can create a cache of all the DHT data (by using the index of the data from the blockchain). We plan on creating such caches (e.g., in memcached servers) and providing easy access to the data through an API. Remember that anyone can verify that the data they received is correct by checking the hash of the data in the blockchain (so you're not trusting the DHT or the cache server).

#### Can I build and host my own index/cache of the data in the DHT?

Absolutely! Anyone can. See above. 

#### Is OP_RETURN the only way to embed the operation data in the blockchain?

Currently, yes. However, we recognize the potential to use multi-sig transaction outputs and standard pay-to-pubkey-hash transaction outputs. If you think it's a good idea to add these options, open an issue and we'll discuss it.

#### Why do I have to preorder a name before registering it?

If we didn't require a step before registration, someone could just see that you're broadcasting the registration of a particular name and race you to have their registration included in the next block. By separating the registration into two steps, we're able to support the pre-registration of an undisclosed name followed by the public confirmation of the registration of that name.

#### Isn't it essentially free for miners to register names?

With the current code, yes. That said, we have a fix for this (see the issues) and we'll have this taken care of before the system goes live.

#### Is there support for names that don't ever expire?

Yes. Each namespace has it's own settings, so if you'd like to register names that don't expire, simply use a namespace that has a flag set for non-expiration.

#### If my I update my profile daily, my transaction costs will be high. Can I avoid this?

There are a few ways to avoid this. The first method is to put the somewhat consistent profile data in the main blob, then include a pointer to a JSON file that has the extended data. Profile explorers will read the data in the file as an extension of the main blob, so updating the file will let you update the profile data without issuing a new transaction and updating the hash associated with the name. You can learn more in the openname specifications repo.

#### Can a name be owned by a multi-sig address?

Absolutely. In this system, names are owned by scriptPubKeys, so all scriptPubKey types that Bitcoin supports are supported here.
