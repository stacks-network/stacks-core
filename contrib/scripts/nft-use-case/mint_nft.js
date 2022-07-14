import {
    makeContractCall,
    AnchorMode,
    standardPrincipalCV,
    uintCV
  } from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';
  

async function main() {
  const network = new StacksTestnet({url: HIRO_MOCKNET_DEFAULT});
  const senderKey = process.env.USER_KEY; 
  const addr = process.env.USER_ADDR;
  const nonce = parseInt(process.argv[2]);
  
  const txOptions = {
      contractAddress: addr, 
      contractName: 'simple-nft-l1', 
      functionName: 'gift-nft',
      functionArgs: [standardPrincipalCV(addr), uintCV(5)],
      senderKey,
      validateWithAbi: false,
      network,
      anchorMode: AnchorMode.Any,
      fee: 10000, 
      nonce
  };
  
  const transaction = await makeContractCall(txOptions);
  
  console.log(transaction.serialize().toString('hex'));
}
 
main()