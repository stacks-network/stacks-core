import {
    makeContractCall,
    AnchorMode,
    standardPrincipalCV,
    uintCV,
    PostConditionMode
  } from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';
  

async function main() {
  const network = new StacksTestnet({url: HIRO_MOCKNET_DEFAULT});
  const senderKey = process.env.USER_KEY;
  const addr = process.env.USER_ADDR;
  const nonce = parseInt(process.argv[2]);
  
  const txOptions = {
      contractAddress: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
      contractName: 'hyperchain',
      functionName: 'deposit-stx',
      functionArgs: [
          uintCV(500_000_000_000), // ID
          standardPrincipalCV(addr), // sender
        ],
      senderKey,
      validateWithAbi: false,
      network,
      anchorMode: AnchorMode.Any,
      fee: 10000,
      postConditionMode: PostConditionMode.Allow,
      nonce,
  };
  
  const transaction = await makeContractCall(txOptions);
  
  console.log(transaction.serialize().toString('hex'));
}
 
main()