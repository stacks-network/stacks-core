import {
    makeContractCall,
    AnchorMode,
    standardPrincipalCV,
    uintCV,
    contractPrincipalCV,
    PostConditionMode,
    broadcastTransaction,
} from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';


async function main() {
    const network = new StacksTestnet({url: HIRO_MOCKNET_DEFAULT});
    const senderKey = process.env.USER_KEY;
    const addr = process.env.USER_ADDR;
    const nonce = parseInt(process.argv[2]);

    const txOptions = {
        contractAddress: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
        contractName: 'hc-alpha',
        functionName: 'deposit-nft-asset',
        functionArgs: [
            uintCV(5), // ID
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
        nonce
    };

    const transaction = await makeContractCall(txOptions);

    const txid = await broadcastTransaction(
        transaction, network
    );

    console.log(txid);
}

main()