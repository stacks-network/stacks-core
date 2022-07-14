import {
  AnchorMode,
  makeContractDeploy
} from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';
import { readFileSync } from 'fs';

async function main() {
  
  const contractName = process.argv[2];
  const contractFilename = process.argv[3];
  const networkLayer = parseInt(process.argv[4]);
  const nonce = parseInt(process.argv[5]);
  const senderKey = process.env.USER_KEY;
  const networkUrl = networkLayer == 2 ? process.env.HYPERCHAIN_API_URL : HIRO_MOCKNET_DEFAULT ;

  const codeBody = readFileSync(contractFilename, { encoding: 'utf-8' });

  const transaction = await makeContractDeploy({
    codeBody, contractName, senderKey, network: new StacksTestnet({url: networkUrl}),
    anchorMode: AnchorMode.Any, fee: 10000, nonce
  });

  console.log(transaction.serialize().toString('hex'));
}


main()