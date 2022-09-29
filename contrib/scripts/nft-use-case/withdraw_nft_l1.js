import {
    makeContractCall,
    deserializeCV,
    AnchorMode,
    standardPrincipalCV,
    uintCV,
    PostConditionMode,
    contractPrincipalCV,
    broadcastTransaction,
} from '@stacks/transactions';
import { StacksTestnet, HIRO_MOCKNET_DEFAULT } from '@stacks/network';


// NOTE: The arguments to the `withdraw-nft-asset` function change with Stacks 2.1
async function main() {
    const network = new StacksTestnet({url: HIRO_MOCKNET_DEFAULT});
    const hyperchainUrl = process.env.HYPERCHAIN_URL;
    const senderKey = process.env.AUTH_HC_MINER_KEY;
    const addr = process.env.ALT_USER_ADDR;
    const contractAddr = process.env.USER_ADDR;
    const withdrawalBlockHeight = process.argv[2];
    const nonce = parseInt(process.argv[3]);
    const withdrawalId = 0;

    let json_merkle_entry = await fetch(`${hyperchainUrl}/v2/withdrawal/nft/${withdrawalBlockHeight}/${addr}/${withdrawalId}/${contractAddr}/simple-nft-l2/nft-token/5`).then(x => x.json())
    let cv_merkle_entry = {
        withdrawal_leaf_hash: deserializeCV(json_merkle_entry.withdrawal_leaf_hash),
        withdrawal_root: deserializeCV(json_merkle_entry.withdrawal_root),
        sibling_hashes: deserializeCV(json_merkle_entry.sibling_hashes),
    };


    const txOptions = {
        senderKey,
        network,
        anchorMode: AnchorMode.Any,
        contractAddress: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
        contractName: "hc-alpha",
        functionName: "withdraw-nft-asset",
        functionArgs: [
            uintCV(5), // ID
            standardPrincipalCV(addr), // recipient
            contractPrincipalCV(contractAddr, 'simple-nft-l1'), // nft-contract
            contractPrincipalCV(contractAddr, 'simple-nft-l1'), // nft-mint-contract
            cv_merkle_entry.withdrawal_root, // withdrawal root
            cv_merkle_entry.withdrawal_leaf_hash, // withdrawal leaf hash
            cv_merkle_entry.sibling_hashes ], // sibling hashes
        fee: 10000,
        postConditionMode: PostConditionMode.Allow,
        nonce,
    }

    const transaction = await makeContractCall(txOptions);

    const txid = await broadcastTransaction(
        transaction, network
    );

    console.log(txid);
}

main()
