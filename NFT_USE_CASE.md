In this demo, you will learn how to:
1. Publish an NFT contract on the Stacks (L1) chain & hyperchain (L2) respectively.
2. Register NFT asset with the hyperchain interface contract.
3. Mint an NFT on the L1 chain.
4. Deposit that NFT to the hyperchain.
5. Transfer the NFT in the hyperchain.
6. Withdraw the NFT back to the L1 chain, which has two steps.

This guide will follow the list above, step by step.
It is also possible to mint assets directly on the hyperchain, and withdraw them onto the L1. This bonus step is mentioned
at the end of step 5. 

## Hyperchains Background
A hyperchain is a network that is separate from the Stacks chain. A hyperchain can be thought of as a layer-2 (L2), 
and the Stacks chain can be thought of as a layer-1 (L1). The hyperchain interfaces with the Stacks chain via a smart 
contract that is specific to it. Different hyperchain networks will use distinct Stacks contracts as an interface. 
This interface contract has several functions that allow it to act as an intermediary between the Stacks chain and 
some particular hyperchain. These functions include but are not limited to:
- `commit-block`: Called by hyperchain miners to record block hashes and withdrawal state on the Stacks chain.
- `deposit-ft-asset` / `deposit-stx` / `deposit-nft-asset`: Called by users to deposit assets into the hyperchains 
  contract. The Hyperchain "listens" for calls to these functions, and performs a mint on the hyperchains to 
  replicate this state. Meanwhile, on the L1, the assets live in the contract.
- `withdraw-ft-asset` / `withdraw-stx` / `withdraw-nft-asset`: Called by miners to withdraw assets from the hyperchain. 

In order to register new allowed assets, a valid miner may call `setup-allowed-contracts`, `register-ft-contract`, or `register-nft-contract`. 
The transaction sender must be part of the miners list defined in the hyperchains contract.

## Setup

Make sure you have `clarinet` installed locally, and that it is at version 0.33.0 or above.
If you do not have clarinet, you can find installation instructions [here](https://github.com/hirosystems/clarinet).

Let's create a new clarinet project. This will create a new directory with a Clarinet project initialized.
```
clarinet new nft-use-case 
```

Let us copy contract files and scripts over from the `stacks-hyperchains` repository into the `nft-use-case` directory. 
If you don't already have the stacks-hyperchains repository, you can clone it [here](https://github.com/hirosystems/stacks-hyperchains).
Set the environment variable `HYPERCHAIN_PATH` to the location of the stacks-hyperchains repository on your computer. 
```
export HYPERCHAIN_PATH=<YOUR_PATH_HERE>
```

Now, we can copy files from the stacks-hyperchains repository. 
```
mkdir nft-use-case/contracts-l2
mkdir nft-use-case/scripts
cp $HYPERCHAIN_PATH/core-contracts/contracts/helper/simple-nft.clar nft-use-case/contracts/
cp $HYPERCHAIN_PATH/core-contracts/contracts/helper/trait-standards.clar nft-use-case/contracts/
cp $HYPERCHAIN_PATH/core-contracts/contracts/helper/simple-nft-l2.clar nft-use-case/contracts-l2/
cp $HYPERCHAIN_PATH/core-contracts/contracts/helper/trait-standards.clar nft-use-case/contracts-l2/
cp $HYPERCHAIN_PATH/contrib/scripts/nft-use-case/* nft-use-case/scripts/
cd nft-use-case/scripts
```

To use the scripts in this demo, we need to install some NodeJS libraries. 
Before running the following instructions, make sure you have [node](https://nodejs.org/en/) installed. 
```
npm install
```

Make the following change in the `settings/Devnet.toml` file in the `nft-use-case` directory to enable the hyperchain:
```
[devnet]
...
enable_hyperchain_node = true
```

Let's spin up a hyperchain node. 
```
clarinet integrate
```

Before we publish any transactions, you will need to set up some environment variables. Open a 
separate terminal window, navigate to the directory `nft-use-case/scripts`, and enter the following. 
```
export AUTH_HC_MINER_ADDR=ST3AM1A56AK2C1XAFJ4115ZSV26EB49BVQ10MGCS0
export AUTH_HC_MINER_KEY=7036b29cb5e235e5fd9b09ae3e8eec4404e44906814d5d01cbca968a60ed4bfb01

export USER_ADDR=ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND
export USER_KEY=f9d7206a47f14d2870c163ebab4bf3e70d18f5d14ce1031f3902fbbc894fe4c701

export ALT_USER_ADDR=ST2REHHS5J3CERCRBEPMGH7921Q6PYKAADT7JP2VB
export ALT_USER_KEY=3eccc5dac8056590432db6a35d52b9896876a3d5cbdea53b72400bc9c2099fe801

export HYPERCHAIN_URL="http://localhost:30443"
```

## Step 1: Publish the NFT contract to the Stacks L1 and the Hyperchain
Once the Stacks node and the hyperchain boots up (use the indicators in the top right panel to determine this), we can 
start to interact with the chains. To begin with, we want to publish NFT contracts onto both the L1 and L2. When the user
deposits their L1 NFT onto the hyperchain, their asset gets minted by the L2 NFT contract. 
The publish script takes in two arguments: the layer on which to broadcast the transaction (1 or 2), and the nonce of the transaction.
First, publish the layer 1 contracts. You can enter this command (and the following transaction commands) in the same 
terminal window as you entered the environment variables. Make sure you are in the `scripts` directory. 
```
node ./publish_tx.js trait-standards ../contracts/trait-standards.clar 1 0 
node ./publish_tx.js simple-nft-l1 ../contracts/simple-nft.clar 1 1
```

Verify that the contracts were published by using the Clarinet console.
For the layer 1 contracts, you should see the following in the "transactions" region in a recent block.

🟩  deployed: ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND.trait-standards (ok true)              

🟩  deployed: ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND.simple-nft-l1 (ok true)

Then, publish the layer 2 contracts. 
```
node ./publish_tx.js trait-standards ../contracts-l2/trait-standards.clar 2 0 
node ./publish_tx.js simple-nft-l2 ../contracts-l2/simple-nft-l2.clar 2 1 
```

To verify that the layer 2 contracts were successfully published, grep the hyperchains log for the transaction IDs 
of *each* hyperchain transaction.
The transaction ID is logged to the console after the call to `publish_tx` - make sure this is the ID you grep for.
```
docker logs hyperchain-node.nft-use-case.devnet 2>&1 | grep "17901e5ad0587d414d5bb7b1c24c3d17bb1533f5025d154719ba1a2a0f570246"
```

Look for a log line similar to the following in the results:
```
Jul 19 12:34:41.683519 INFO Tx successfully processed. (ThreadId(9), src/chainstate/stacks/miner.rs:235), event_name: transaction_result, tx_id: 17901e5ad0587d414d5bb7b1c24c3d17bb1533f5025d154719ba1a2a0f570246, event_type: success, payload: SmartContract
```

## Step 2: Register the new asset in the interface hyperchain contract
Create the transaction to register the new asset. This is going to be called by a miner of the hyperchains contract.
Specifically, this transaction will be sent by `AUTH_HC_MINER_ADDR`. 
```
node ./register_nft.js 0
```
Look for the following transaction confirmation in the Clarinet console in an upcoming block on the layer 1.

🟩  invoked: ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.hyperchain::register-new-nft-contract(ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.simple-nft-l1, "hyperchain-deposit-nft-token") (ok true)

## Step 3: Mint an NFT on the L1 Chain
Let's create a transaction to mint an NFT on the L1 chain. Once this transaction is processed, the principal `USER_ADDR`
will own an NFT. 
```
node ./mint_nft.js 2 
```
Verify that the transaction is acknowledged within the next few blocks in the Stacks explorer.

🟩  invoked: ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND.simple-nft-l1::gift-nft(ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND, u5) (ok true)

## Step 4: Deposit the NFT onto the Hyperchain 
Now, we can call the deposit NFT function in the hyperchains interface contract. This 
function is called by the principal `USER_ADDR`. 
```
node ./deposit_nft.js 3
```
Verify that the transaction is acknowledged in the next few blocks of the L1 chain. 
After the transaction is confirmed on the L1, you also may want to verify that the asset was successfully deposited 
on the hyperchain by grepping for the deposit transaction ID. 
```
docker logs hyperchain-node.nft-use-case.devnet 2>&1 | grep "67cfd6220ed01c3aca3912c8f1ff55d374e5b3acadb3b995836ae913108e0514"
```
Look for a line like:
```
Jul 19 12:51:02.396923 INFO ACCEPTED burnchain operation (ThreadId(8), src/chainstate/burn/db/sortdb.rs:3042), op: deposit_nft, l1_stacks_block_id: 8b5c4eb05afae6daaafdbd59aecaade6da1a8eab5eb1041062c6381cd7104b75, txid: 67cfd6220ed01c3aca3912c8f1ff55d374e5b3acadb3b995836ae913108e0514, l1_contract_id: ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.simple-nft-l1, hc_contract_id: ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.simple-nft-l2, hc_function_name: hyperchain-deposit-nft-token, id: 5, sender: ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG
```

## Step 5: Transfer the NFT within the Hyperchain 
On the hyperchains, the NFT should belong to the principal that sent the deposit transaction, `USER_ADDR`. 
This principal can now transfer the NFT within the hyperchain. Let's transfer the NFT to `ALT_USER_ADDR`. 
```
node ./transfer_nft.js 2
```
Grep for the transaction ID of the transfer transaction. 
```
docker logs hyperchain-node.nft-use-case.devnet 2>&1 | grep "74949992488b2519e2d8408169f242c86a6cdacd927638bd4604b3b8d48ea187"
```

Look for something like the following line:
```
Jul 19 13:04:43.177993 INFO Tx successfully processed. (ThreadId(9), src/chainstate/stacks/miner.rs:235), event_name: transaction_result, tx_id: 74949992488b2519e2d8408169f242c86a6cdacd927638bd4604b3b8d48ea187, event_type: success, payload: ContractCall
```

For a bonus step, you can try minting an NFT on the hyperchain. This would require calling the `gift-nft` function in the 
contract `simple-nft-l2`. You can tweak the `transfer_nft.js` file to make this call. 

## Step 6: Withdraw the NFT back to the L1 Chain
### Background on withdrawals
Withdrawals from the hyperchain are a 2-step process. 

The owner of an asset must call `withdraw-ft?` / `withdraw-stx?` / `withdraw-nft?` in a Clarity contract on the hyperchain,
which destroys those assets on the hyperchain, and adds that particular withdrawal to a withdrawal Merkle tree for that block.
The withdrawal Merkle tree serves as a cryptographic record of the withdrawals in a particular block. The root of this
Merkle tree is committed to the L1 interface contract via the `commit-block` function.

The second step involves calling the appropriate withdraw function in the hyperchains interface 
contract on the L1 chain. You must also pass in the "proof" that corresponds to your withdrawal. 
This proof includes the root hash of the withdrawal Merkle tree that this withdrawal was included in, 
the leaf hash of the withdrawal itself, and a list of hashes to be used to prove that the leaf is valid. Currently, 
this function must be called by a hyperchain miner, but in an upcoming hyperchain release, the asset owner must call 
this function. 

### Step 6a: Withdraw the NFT on the hyperchain 
Perform the withdrawal on the layer 2 by calling `withdraw-nft-asset` in the `simple-nft-l2` contract. This will be called 
by the principal `ALT_USER_ADDR`.
```
node ./withdraw_nft_l2.js 0 
```
Grep the hyperchain node to ensure success:
```
docker logs hyperchain-node.nft-use-case.devnet 2>&1 | grep "3ff9b9b0f33dbd6087f302fa9a7a113466cf7700ba7785a741b391f5ec7c5ba4"
Jul 19 13:07:33.804109 INFO Tx successfully processed. (ThreadId(9), src/chainstate/stacks/miner.rs:235), event_name: transaction_result, tx_id: 3ff9b9b0f33dbd6087f302fa9a7a113466cf7700ba7785a741b391f5ec7c5ba4, event_type: success, payload: ContractCall

docker logs hyperchain-node.nft-use-case.devnet 2>&1 | grep "withdraw-nft-asset"
Jul 19 13:22:34.800652 INFO Contract-call successfully processed (ThreadId(8), src/chainstate/stacks/db/transactions.rs:731), contract_name: ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.simple-nft-l2, function_name: withdraw-nft-asset, function_args: [u5, ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC], return_value: (ok true), cost: ExecutionCost { write_length: 2, write_count: 2, read_length: 1647, read_count: 5, runtime: 2002000 }
```

In order to successfully complete the withdrawal on the L1, it is necessary to know the height at which the withdrawal occurred. 
You can find the height of the withdrawal using grep:
```
docker logs hyperchain-node.nft-use-case.devnet 2>&1 | grep "Parsed L2 withdrawal event"
Jul 19 13:22:34.801290 INFO Parsed L2 withdrawal event (ThreadId(8), src/clarity_vm/withdrawal.rs:56), type: nft, block_height: 47, sender: ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC, withdrawal_id: 0, asset_id: ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.simple-nft-l2::nft-token
```
Get the withdrawal height by looking at the `block_height` in the returned line. There may be multiple lines returned 
by the grep. Try the higher heights first, and work backward. 

### Step 6b: Complete the withdrawal on the Stacks chain 
Use the withdrawal height we just obtained from the grep and substitute that for `WITHDRAWAL_BLOCK_HEIGHT`.
You might need to wait a little bit for the hyperchain block to become official (even if
the grep already returned a result) for the transaction to succeed.
```
node ./withdraw_nft_l1.js {WITHDRAWAL_BLOCK_HEIGHT} 1
```

Check for the success of this transaction in the Clarinet console:

🟩  invoked: ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.hyperchain::withdraw-nft-asset(u5, ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05...

You can also navigate to the Stacks Explorer (the URL of this will be listed in the Clarinet console), and check that the expected 
principal now owns the NFT (`ALT_USER_ADDR`). You can check this by clicking on the transaction corresponding to 
`withdraw-nft-asset`. 


That is the conclusion of this demo! If you have any issues with this demo, reach out on the Stacks Discord or leave an issue in the 
stacks-hyperchains repository.