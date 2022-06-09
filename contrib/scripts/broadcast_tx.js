const network = require('@stacks/network');
const transactions = require('@stacks/transactions');
const fs = require('fs');

async function main() {
  const txFilename = process.argv[2];
  const endpoint = process.argv[3];
  const myNet = new network.StacksTestnet();
  if (endpoint) {
    myNet.coreApiUrl = endpoint;
  }
  const txHex = fs.readFileSync(txFilename, { encoding: 'utf-8' });
  const transaction = transactions.deserializeTransaction(Buffer.from(txHex, 'hex'));
  const txid = await transactions.broadcastTransaction(
    transaction, myNet
  );

  console.log(txid);
}


main()
