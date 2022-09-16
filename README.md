# Subnets

Subnets are a layer-2 scaling solution in the Stacks blockchain that offers low latency and high throughput workloads. It enables developers to build fast and reliable experiences on Stacks.

## Overview

Subnets are designed to transact on Stacks assets, meaning users can move assets in and out of subnets. While a user’s assets are in a subnet, they trust that subnet’s consensus rules. This subnet will interact with the Stacks chain using a smart contract specific to that subnet.

>[!Note]
> The current implementation of subnets uses a 2-phase commit protocol amongst a fully-trusted pool of miners.

Below are some of the features of subnets:

- Each subnet may define its throughput settings. The default implementation should support at least 4x high throughput for transactions and may reduce confirmation time from 10 minutes to 1 minute.
- Interacting with a subnet is similar to interacting with a different Stacks network (example: testnet vs. mainnet).
- The Stacks blockchain can support many different subnets.
- Each subnet may use the same or different consensus rules.
- This repository implements a consensus mechanism that uses a two-phase commit among a federated pool of miners.
- To deposit into a subnet, users submit a layer-1 transaction to invoke the deposit method on that subnet's smart contract.
- For withdrawals, users commit the withdrawal on the subnet and then submit a layer-1 transaction to invoke the subnet's smart contract's withdraw method.

## Architecture

This diagram outlines the interaction between a subnet and the Stacks layer-1 chain.

![Architecture of subnets.](hiro-docs/docs/images/subnets-architecture.png)

When a miner proposes a block to the other miners, the other miners must approve and sign the block before it can be committed to the subnet.

![Screenshot of subnet miners proposing and approving the blocks.](hiro-docs/docs/images/subnet-miners.png)

### Trust models in subnets

The current implementation of subnets uses a federated system of miners. This federation is fully-trusted, but future work on subnets will explore alternative trust models.

In a fully - trusted model:

- Miners are responsible for issuing subnet blocks.
- Users can validate, but subnet miners control withdrawals.
- Trust can be federated with a 2-phase commit and BFT protocol for miner block issuance.
- Federation requires a majority of miners to approve withdrawals.

## Getting started

You can start with an NFT use case demo [here](https://github.com/hirosystems/stacks-subnets/blob/master/NFT_USE_CASE.md).

## Resources

- [Introductions to subnets.](https://www.youtube.com/watch?v=PFPwuVCGGuI)
- [Introducing subnets blog post.](https://www.hiro.so/blog/introducing-hyperchains-by-hiro)
- [Update on subnets, a scaling solution for Stacks.](https://www.hiro.so/blog/an-update-on-hyperchains-a-scaling-solution-for-stacks)
