import {
    makeContractCall,
    AnchorMode,
    standardPrincipalCV,
    uintCV,
    contractPrincipalCV,
    PostConditionMode
  } from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';
  

async function main() {
  const network = new StacksTestnet({url: HIRO_MOCKNET_DEFAULT});
  const senderKey = process.env.USER_KEY; 
  const addr = process.env.USER_ADDR;
  
  const txOptions = {
      contractAddress: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
      contractName: 'hyperchain',
      functionName: 'deposit-nft-asset',
      functionArgs: [
          uintCV(6), // ID
          standardPrincipalCV(addr), // sender
          contractPrincipalCV(addr, 'simple-nft-l1'), // contract ID of nft contract on L1
          contractPrincipalCV(addr, 'simple-nft-l2'), // contract ID of nft contract on L2
        ],
      senderKey,
      validateWithAbi: false,
      network,
      anchorMode: AnchorMode.Any,
      fee: 10000, 
      postConditionMode: PostConditionMode.Allow,
  };
  
  const transaction = await makeContractCall(txOptions);
  
  console.log(transaction.serialize().toString('hex'));
}
 
main()