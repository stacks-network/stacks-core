# Stacks Network Testing

A rudimentary set of tools for testing multiple Stacks nodes at once, locally.
Relevant files:

* `bin/start.sh` -- start up a master node, a miner node, or a follower node, as
  well as ancilliary processes.
* `bin/faucet.sh` -- a rudimentary Bitcoin faucet.
* `bin/txload.sh` -- a rudimentary Stacks transaction generator and load-tester.
* `etc/*.in` -- templates that `bin/start.sh` uses to create configuration
  files.

To use, you will need to install `stacks-node`, `blockstack-cli`,
`puppet-chain`, and `bin/faucet.sh` to somewhere in your `$PATH`.
You will also need a recent `bitcoind` and `bitcoin-cli`.
