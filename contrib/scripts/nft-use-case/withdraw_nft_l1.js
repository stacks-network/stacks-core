import {
    makeContractCall,
    deserializeCV,
    AnchorMode,
    standardPrincipalCV,
    uintCV,
    PostConditionMode,
    contractPrincipalCV
  } from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';
  

async function main() {
  const network = new StacksTestnet({url: HIRO_MOCKNET_DEFAULT});
  const senderKey = process.env.ALT_USER_KEY;
  const addr = process.env.ALT_USER_ADDR;
  const contractAddr = process.env.USER_ADDR;
  const withdrawalBlockHeight = process.argv[2];
  const nonce = parseInt(process.argv[3]);

  // TODO: switch URL to hyperchains API 
  // let json_merkle_entry = await fetch(`http://localhost:3999/v2/withdrawal/nft/${withdrawalBlockHeight}/ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG/0/50000`).then(x => x.json())
  let json_merkle_entry = await fetch(`http://localhost:3999/v2/withdrawal/nft/${withdrawalBlockHeight}/${addr}/0/50000`).then(x => x.json())
  let cv_merkle_entry = {
      withdrawal_leaf_hash: deserializeCV(json_merkle_entry.withdrawal_leaf_hash),
      withdrawal_root: deserializeCV(json_merkle_entry.withdrawal_root),
      sibling_hashes: deserializeCV(json_merkle_entry.sibling_hashes),
  };


  const txOptions = {
    senderKey, network, anchorMode: AnchorMode.Any,
    contractAddress: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
    contractName: "hyperchain",
    functionName: "withdraw-nft-asset",
    functionArgs: [ 
        uintCV(5), // ID
        standardPrincipalCV(addr), // recipient
        contractPrincipalCV(contractAddr, 'simple-nft-l1'),
        // contractPrincipalCV('ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5', 'simple-nft-l1'), // contract ID of nft contract on L1
        cv_merkle_entry.withdrawal_root, // withdrawal root
        cv_merkle_entry.withdrawal_leaf_hash, // withdrawal leaf hash 
        cv_merkle_entry.sibling_hashes ], // sibling hashes 
    fee: 10000,
    postConditionMode: PostConditionMode.Allow,
    nonce,
 }
  
  const transaction = await makeContractCall(txOptions);
  
  console.log(transaction.serialize().toString('hex'));
}
 
main()