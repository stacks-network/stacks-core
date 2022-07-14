import {
    deserializeTransaction,
    broadcastTransaction,
  } from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';
import { readFileSync } from 'fs'; 

async function main() {
  const txFilename = process.argv[2];
  const networkLayer = parseInt(process.argv[3]);
  const txHex = readFileSync(txFilename, { encoding: 'utf-8' });
  const transaction = deserializeTransaction(Buffer.from(txHex, 'hex'));
  // TODO: check URL for hyperchains
  const networkUrl = networkLayer == 2 ? process.env.HYPERCHAIN_API_URL : HIRO_MOCKNET_DEFAULT;

  const txid = await broadcastTransaction(
    transaction, new StacksTestnet({url: networkUrl})
  );

  console.log(txid);
}


main()