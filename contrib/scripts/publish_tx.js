const network = require('@stacks/network');
const transactions = require('@stacks/transactions');
const fs = require('fs');

async function main() {
  const senderKey = process.env.CONTRACT_PUBLISH_KEY;
  const contractName = process.argv[2];
  const contractFilename = process.argv[3];
  const nonce = parseInt(process.argv[4]);

  const codeBody = fs.readFileSync(contractFilename, { encoding: 'utf-8' });

  const transaction = await transactions.makeContractDeploy({
    codeBody, contractName, senderKey, network: new network.StacksTestnet(),
    anchorMode: transactions.AnchorMode.Any, nonce
  });

  console.log(transaction.serialize().toString('hex'));
}


main()
