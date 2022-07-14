In this demo, you will learn how to:
1. Publish an NFT contract on the Stacks (L1) chain & hyperchain (L2) respectively.
2. Register NFT asset with the hyperchain interface contract.
3. Mint an NFT on the L1 chain.
4. Deposit that NFT to the hyperchain.
5. Transfer the NFT in the hyperchain.
6. Withdraw the NFT back to the L1 chain, which has two steps.

This guide will follow the list above, step by step.

## Hyperchains Background
A hyperchain is a network that is separate from the Stacks chain. A hyperchain can be thought of as a layer-2 (L2), and the Stacks chain can be thought of as a layer-1 (L1). The hyperchain interfaces with the Stacks chain via a smart contract that is specific to it. Different hyperchain networks will use distinct Stacks contracts as an interface. This interface contract has several functions that allow it to act as an intermediary between the Stacks chain and some particular hyperchain. These functions include but are not limited to:
- `commit-block`: Called by hyperchain miners to record block hashes and withdrawal state on the Stacks chain.
- `deposit-ft-asset` / `deposit-stx` / `deposit-nft-asset`: Called by users to deposit assets into the hyperchains contract. The Hyperchain "listens" for calls to these functions, and performs a mint on the hyperchains to replicate this state. Meanwhile, on the L1, the assets live in the contract.
- `withdraw-ft-asset` / `withdraw-stx` / `withdraw-nft-asset`: Called by users to withdraw assets from the hyperchain. Withdrawals require two steps. (1) The owner of an asset must call `withdraw-ft?` / `withdraw-stx?` / `withdraw-nft?` in a Clarity contract on the hyperchain, which destroys those assets on the hyperchain, and adds that particular withdrawal to a withdrawal Merkle tree for that block. Thed withdrawal Merkle tree serves as a cryptographic record of the withdrawals in a particular block. The root of this Merkle tree is committed to the L1 via the `commit-block` function. (2) Users now call the corresponding withdraw function on the Hyperchains interface contract, which transfers the asset from the contract itself and/or mints the requested asset.

In order to register new allowed assets, a valid miner may call `setup-allowed-contracts`, `register-ft-contract`, or `register-nft-contract`. It's key that the transaction sender is part of the miners list defined in the hyperchains contract. For the sake of this demo, we will use the following accounts:
### Account 1 - is a miner on the hyperchains contract
- secret_key: 7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801
- stx_address: ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5
- btc_address: mr1iPkD9N3RJZZxXRk7xF9d36gffa6exNC
### Account 2
- secret_key: 530d9f61984c888536871c6573073bdfc0058896dc1adfe9a6a10dfacadc209101
- stx_address: ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG
- btc_address: muYdXKmX9bByAueDe6KFfHd5Ff1gdN9ErG

## Setup

Make sure you have `clarinet` installed locally, and that it is at version 0.32.0 or above.
If you do not have clarinet, you can find installation instructions [here](https://github.com/hirosystems/clarinet).

Let's create a new clarinet project. This will create a new directory with a Clarinet project initialized.
```
❯ clarinet new nft-use-case 
```

Let us copy contract files and scripts over from the `stacks-hyperchains` repository into the `nft-use-case` directory. Be sure to replace `...` with the appropriate file path on your machine.
```
mkdir nft-use-case/contracts-l2
mkdir nft-use-case/scripts
cp ~/.../stacks-hyperchains/core-contracts/contracts/helper/simple-nft.clar nft-use-case/contracts/
cp ~/.../stacks-hyperchains/core-contracts/contracts/helper/trait-standards.clar nft-use-case/contracts/
cp ~/.../stacks-hyperchains/core-contracts/contracts/helper/simple-nft-l2.clar nft-use-case/contracts-l2/
cp ~/.../stacks-hyperchains/core-contracts/contracts/helper/trait-standards.clar nft-use-case/contracts-l2/
cp ~/.../stacks-hyperchains/contrib/scripts/nft-use-case/* nft-use-case/scripts/
cd nft-use-case/scripts
npm install @stacks/transactions
npm install @stacks/network
mkdir ../transactions/
```

Make the following changes in the `Devnet.toml` file in the `nft-use-case` directory (make sure these lines are uncommented and set to these values):
TODO: double check + change image name
```
[devnet]
...
enable_hyperchain_node = true
hyperchain_leader_mnemonic = "female adjust gallery certain visit token during great side clown fitness like hurt clip knife warm bench start reunion globe detail dream depend fortune"
hyperchain_contract_id = "STXMJXCJDCT4WPF2X1HE42T6ZCCK3TPMBRZ51JEG.hyperchain"
hyperchain_node_image_url = "localhost:5000/pavi:latest"

```
Let's spin up a hyperchain node:
```
clarinet integrate
```

Before we publish any transactions, you will need to set the private key of the contract publisher as an env var (the private key used here corresponds to a valid miner in the list).
```
export AUTH_HC_MINER_ADDR=ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5
export AUTH_HC_MINER_KEY=7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801

wallet 2
export USER_KEY=530d9f61984c888536871c6573073bdfc0058896dc1adfe9a6a10dfacadc209101
export USER_ADDR=ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG

wallet 3
export ALT_USER_KEY=d655b2523bcd65e34889725c73064feb17ceb796831c0e111ba1a552b0f31b3901
export ALT_USER_ADDR=ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC

export HYPERCHAIN_API_URL="http://localhost:13999"
```

## Step 1: Publish the NFT contract to the Stacks L1 and the Hyperchain
Once the Stacks node and the hyperchain boots up (use the indicators in the top right panel to determine this), we can publish these contracts.
```
node ./publish_tx.js trait-standards ../contracts/trait-standards.clar 1 0 > ../transactions/trait-publish-l1.hex
node ./publish_tx.js simple-nft-l1 ../contracts/simple-nft.clar 1 1 > ../transactions/contract-publish-l1.hex
node ./publish_tx.js trait-standards ../contracts-l2/trait-standards.clar 2 0 > ../transactions/trait-publish-l2.hex
node ./publish_tx.js simple-nft-l2 ../contracts-l2/simple-nft-l2.clar 2 1 > ../transactions/contract-publish-l2.hex
```
Then, broadcast the publish transactions. The broadcast script used in this demo takes in two arguments: the hex of a transaction, and the layer to broadcast the transaction (1 or 2).
```
node ./broadcast_tx.js ../transactions/trait-publish-l1.hex 1
{
  txid: '8ac12925ff21fd70042770d2f381e47c103ab11efb0facbc6b0359c95a0da046'
}
node ./broadcast_tx.js ../transactions/contract-publish-l1.hex 1
{
  txid: '2056c48f67887a4e858e3611a4d5b83c43fe8a73f17af4621d77a63b6d802d9b'
}
node ./broadcast_tx.js ../transactions/trait-publish-l2.hex 2
{
  txid: '8ac12925ff21fd70042770d2f381e47c103ab11efb0facbc6b0359c95a0da046'
}
node ./broadcast_tx.js ../transactions/contract-publish-l2.hex 2
{
  txid: '88eb4f4d45c5467ceb96e469af96a71ed5b206f5c298a2f2e8c22c58c6d3e6b4'
}
```
Verify that the contracts were published by using the Clarinet console.
For the layer 1 contracts, you should see the following in the "transactions" region in a recent block.
TODO: explain how to add hyperchain network in explorer
🟩  deployed: ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.trait-standards (ok true)
🟩  deployed: ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.simple-nft-l1 (ok true)

In order to verify, navigate to the Stacks explorer. The url of it should be displayed in the Clarinet integrate UI. At the time of writing this demo, the URL was set to https://localhost:8000 by default. To gain visibility into the hyperchains blocks, navigate to the "Network" drop down in the top right corner of the screen, and click "Add a network". You will now be presented with a screen with two fields, the name of the network and the URL of its API. The hyperchain API url should also be displayed in the clarinet UI, and it should be set to https://localhost:13999 by default.

With the explorer now set up for the hyperchain network, you can verify that the two contract deployments (for 'trait-standards' and 'simple-nft-l2') were successful.

## Step 2: Register the new asset in the interface Hyperchain contract
Create the transaction to register the new asset. This is going to be called by a miner of the hyperchains contract.
// TODO: nonce-1 ???
```
node ./register_nft.js 1 > ../transactions/register-nft.hex
node ./broadcast_tx.js ../transactions/register-nft.hex 1
{
  txid: '783a463658852a4c9b3e5e5f8a5125593ed17ab72ff7338b84660cca43b0710d'
}
```
Look for the following transaction confirmation in an upcoming block.
🟩 invoked: ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.hc::setup-allowed-contracts (ok true)

## Step 3: Mint an NFT on the L1 Chain
The call to `clarinet integrate` will have spun up API instances for both the L1 chain and the hyperchain. We will use the API to submit raw transactions to each chain. We will generate raw transactions using the `@stacks/transactions` library, which you can [download](https://github.com/hirosystems/stacks.js/tree/master/packages/transactions) via npm. To use this library, you must also have [node](https://nodejs.org/en/) installed.
Let's create a transaction to mint an NFT on the L1 chain:
// TODO - nonce-1
```
node ./mint_nft.js 2 > ../transactions/mint-nft.hex
node ./broadcast_tx.js ../transactions/mint-nft.hex 1
{
  txid: 'aba138f8291561579e5807d1e4f505112cf3f6489921b505ef68bb04a4b6f269'
}
```
Verify that the transaction is acknowledged within the next few blocks in the Stacks explorer.
```

TODO: remove curl
You can also check the mint status by pinging issuing a curl:
```
❯ curl -L http://localhost:3999/extended/v1/tokens/nft/mints\?asset_identifier\=ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.simple-nft-l1::nft-token
{
"limit": 50,
"offset": 0,
"total": 1,
"results": [
{
"recipient": "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG",
"event_index": 0,
"value": {
"hex": "0x0100000000000000000000000000000005",
"repr": "u5"
},
"tx_id": "0xaba138f8291561579e5807d1e4f505112cf3f6489921b505ef68bb04a4b6f269"
}
]
}
```

## Step 4: Deposit the NFT onto the Hyperchain 
Now, we can call the deposit NFT function in the hyperchains interface contract that lives on the Stacks L1 chain. 
TODO: nonce-1
```
node ./deposit_nft.js 4 > ../transactions/deposit-nft.hex
node ./broadcast_tx.js ../transactions/deposit-nft.hex 1
{
txid: '227873d7b8496494bd87a15ebac91dfc85c3c20bd27ff43e46c68bca4e50d62f'
}
```
Verify that the transaction is acknowledged in the next few blocks of the L1 chain. You also may want to verify that the asset was successfully minted on the hyperchain. You can navigate to the account page for `USER_ADDR`, and ensure it owns a "collectible" now.  

TODO: remove curl instructions 
You can check that the user's NFT was minted on the hyperchain by calling:
```
curl -L http://localhost:30443/extended/v1/tokens/nft/mints\?asset_identifier\=ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG.simple-nft-l2::nft-token
```

## Step 5: Transfer the NFT within the Hyperchain 
Now, the NFT should belong to the principal that sent the deposit transaction, `ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5. This principal can now transfer the NFT within the hyperchain. 
```
node ./transfer_nft.js 2 > ../transactions/transfer-nft.hex
node ./broadcast_tx.js ../transactions/transfer-nft.hex 2
{
txid: '1e072aa3d8912c2d113fd7b84f59ae311110772a1b867a84e7873fbbb2663374'
}
```
TODO: verification of who owns the asset now - docker logs?

## Step 6: Withdraw the NFT back to the L1 Chain
### Background on withdrawals
Withdrawals from the hyperchain are a 2-step process. 

The first step involves calling one of the Clarity withdraw functions within a smart contract call. This means calling either `stx-withdraw?`, `ft-withdraw?`, or `nft-withdraw?`. These functions only exist in the hyperchains. When a withdraw function succeeds, the hyperchain node adds that withdrawal to a withdrawal Merkle tree for the specific block that the hyperchain is building. When the hyperchain node commits a block, it also submits the root hash of the Merkle tree. 

The second step involves calling the appropriate withdraw function in the hyperchains interface contract on the L1 chain. You must also pass in the "proof" that corresponds to this particular withdrawal. 
This proof includes the root hash of the withdrawal Merkle tree that this withdrawal was included in, the leaf hash of the withdrawal itself, and a list of hashes to be used to prove that the provided leaf belongs to the tree corresponding to the provided root hash. 

### Step 6a: Withdraw the NFT on the hyperchain 
Perform the withdrawal on the layer 2 by calling `withdraw-nft-asset` in the `simple-nft-l2` contract. 
```
node ./withdraw_nft_l2.js 0 > ../transactions/withdraw-nft-l2.hex
node ./broadcast_tx.js ../transactions/withdraw-nft-l2.hex 2
{
txid: '3ff9b9b0f33dbd6087f302fa9a7a113466cf7700ba7785a741b391f5ec7c5ba4'
}
```

### Step 6b: Complete the withdrawal on the Stacks chain 
In order to submit the withdrawal on the L1, we need to pass in the information that proves the withdrawal is valid. To do so, we pass in the hyperchains height at which the withdrawal was processed. Use the Clarinet block explorer to identify the withdrawal height that the withdrawal occurred at (look for a commit-block transaction with a non-zero withdrawal merkle root), and pass that height in where `WITHDRAWAL_BLOCK_HEIGHT` is used below. 
// TODO: ensure you can easily get the HC height 
```
node ./withdraw_nft_l1.js {WITHDRAWAL_BLOCK_HEIGHT} > ../transactions/withdraw-nft-l1.hex
node ./broadcast_tx.cjs ../transactions/withdraw-nft-l1.hex 1
{
TODO
}
```

That is the conclusion of this demo! 
For more information, visit
TODO: add follow up info 




TODO
- figure out how to send tx to hyperchain (network.StacksTestnet...)
- clarify language being used in the demo
    - be clear on Stacks L1 v Hyperchains v L2 
- switch from calling "register" to "setup"
 