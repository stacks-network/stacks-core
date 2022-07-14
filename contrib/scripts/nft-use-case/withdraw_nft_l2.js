import {
    makeContractCall,
    AnchorMode,
    standardPrincipalCV,
    uintCV,
    contractPrincipalCV
  } from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';
  

async function main() {
  const network = new StacksTestnet({url: process.env.HYPERCHAIN_API_URL});
  const senderKey = process.env.ALT_USER_KEY;
  const addr = process.env.USER_ADDR;
  const alt_addr = process.env.ALT_USER_ADDR;
  const nonce = parseInt(process.argv[2]);
  
  const txOptions = {
      contractAddress: addr,
      contractName: 'simple-nft-l2',
      functionName: 'withdraw-nft-asset',
      functionArgs: [
          uintCV(5), // ID
          standardPrincipalCV(alt_addr), // recipient
        ],
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