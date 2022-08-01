import {
    makeContractCall,
    AnchorMode,
    standardPrincipalCV,
    uintCV,
    broadcastTransaction,
    PostConditionMode
} from '@stacks/transactions';
import { StacksTestnet } from '@stacks/network';


async function main() {
    const network = new StacksTestnet({url: process.env.HYPERCHAIN_URL});
    const senderKey = process.env.ALT_USER_KEY;
    const contractAddr = process.env.USER_ADDR;
    const addr = process.env.ALT_USER_ADDR;
    const nonce = parseInt(process.argv[2]);

    const txOptions = {
        contractAddress: contractAddr,
        contractName: 'simple-nft-l2',
        functionName: 'withdraw-nft-asset',
        functionArgs: [
            uintCV(5), // ID
            standardPrincipalCV(addr), // recipient
        ],
        senderKey,
        validateWithAbi: false,
        network,
        anchorMode: AnchorMode.Any,
        fee: 10000,
        nonce,
        postConditionMode: PostConditionMode.Allow,
    };

    const transaction = await makeContractCall(txOptions);

    const txid = await broadcastTransaction(
        transaction, network
    );

    console.log(txid);
}

main()