# Blockstack Core on AWS

We're releasing a listing on the AWS Marketplace, where you can easily deploy
the latest version of Blockstack core (with fastsync support).

- **Step 1:** Login to your AWS account or create one if you don't already have one.

- **Step 2:** Deploy a new VM from the Blockstack image, with at least 20 GB of space on the root volume.

- **Step 3:** Login to your newly deployed node.

- **Step 4:** Use fastsync to get the latest state:

```
$ blockstack-server --debug fast_sync
```

- **Step 5:** Start the Blockstack Core node:

```
$ blockstack-server --debug start
$ tail -f ~/.blockstack-server/blockstack-server.log
```

If you run into any issues, you can talk to us in the #support channel at http://chat.blockstack.org

