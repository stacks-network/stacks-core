import {
    broadcastTransaction,
    getNonce,
    SignedContractCallOptions,
    bufferCVFromString,
    bufferCV,
    uintCV,
    standardPrincipalCV,
    makeContractCall,
    PostConditionMode,
    makeSTXTokenTransfer,    
    SignedTokenTransferOptions,
    AnchorMode
} from '@stacks/transactions';
import {
    StackingClient,
} from '@stacks/stacking';
import { seeders } from './seeders';
import { sponsors } from './sponsors';
import { users as all_users } from './users';
import BN = require("bn.js");
import { StacksTestnet } from '@stacks/network';
import ripemd160 from 'ripemd160';
import shajs from 'sha.js';

const NUMBER_OF_NODES = 9;
const NUMBER_OF_USERS = 2000;

let nodes = [...Array(NUMBER_OF_NODES)].map((_, i) => {
    let node = new StacksTestnet();
    node.coreApiUrl = `http://localhost:2${i+1}443`;
    return node;
});

const BNS_CONTRACT_ADDRESS = "ST000000000000000000002AMW42H";
const BNS_CONTRACT_NAME = "bns";

let namespace = "galabru";
let salt = "0000";
let sha256 = new shajs.sha256().update(`${namespace}${salt}`).digest();
let hash160 = new ripemd160().update(sha256).digest('hex');
let hashed_namespace = bufferCV(Buffer.from(hash160, "hex"))
const namespaceOwner = seeders[0];
const fee = new BN(1000);
let nonce = new BN(0);

let options: SignedContractCallOptions = {
    contractAddress: BNS_CONTRACT_ADDRESS,
    contractName: BNS_CONTRACT_NAME,
    functionName: "namespace-preorder",
    functionArgs: [hashed_namespace, uintCV(6400000000)],
    senderKey: namespaceOwner.secret,
    fee,
    nonce,
    network: nodes[0],
    postConditionMode: PostConditionMode.Allow,
    anchorMode: AnchorMode.OnChainOnly
};

makeContractCall(options).then(async (transaction) => {
    var txId = await broadcastTransaction(transaction, nodes[0]);
    console.log(`TX broadcasted ${txId}`)

    // Reveal the namespace
    var contractCall = await makeContractCall({
        contractAddress: BNS_CONTRACT_ADDRESS,
        contractName: BNS_CONTRACT_NAME,
        functionName: "namespace-reveal",
        functionArgs: [bufferCVFromString(namespace), bufferCVFromString(salt), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(1), uintCV(0), uintCV(1), uintCV(0), standardPrincipalCV(namespaceOwner.address)],
        senderKey: namespaceOwner.secret,
        fee,
        nonce: new BN(1),
        network: nodes[0],
        postConditionMode: PostConditionMode.Allow,
        anchorMode: AnchorMode.OnChainOnly
    });
    txId = await broadcastTransaction(contractCall, nodes[0]);
    console.log(`TX 'namespace-reveal' broadcasted ${txId}`)

    // Reveal the namespace
    contractCall = await makeContractCall({
        contractAddress: BNS_CONTRACT_ADDRESS,
        contractName: BNS_CONTRACT_NAME,
        functionName: "namespace-ready",
        functionArgs: [bufferCVFromString(namespace)],
        senderKey: namespaceOwner.secret,
        fee,
        nonce: new BN(2),
        network: nodes[0],
        postConditionMode: PostConditionMode.Allow,
        anchorMode: AnchorMode.OnChainOnly
    });
    txId = await broadcastTransaction(contractCall, nodes[0]);
    console.log(`TX 'namespace-ready' broadcasted ${txId}`);

    // Use all the other seeders for seeding 80 sponsors,
    // that will fund operations for 2000 users.
    var s = seeders;
    s.shift();
    return Promise.all(
        s.map(seeder => getNonce(seeder.address, nodes[0]))
    )
}).then(async (seeders_nonces) => {
    var round_robin = 0;
    var txids = [];
    let sponsors_nonces = new Array();
    for (let sponsor of sponsors) {
        let index = round_robin % seeders.length;
        let nonce = seeders_nonces[index] as BN;
        let seeder = seeders[index];
        let amount = new BN(1000000000);
        let recipient = sponsor.keyInfo.address;
        const txOptions: SignedTokenTransferOptions = {
            recipient,
            amount,
            senderKey: seeder.secret,
            network: nodes[0],
            memo: 'tests ludo',
            nonce,
            fee: new BN(200),
        };

        seeders_nonces[index] = nonce.addn(1);
        round_robin += 1;

        const transfer = await makeSTXTokenTransfer(txOptions);
        let txid = await broadcastTransaction(transfer, nodes[0]);
        sponsors_nonces.push(new BN(0));
        console.log(`TX '${seeder.address} -> ${amount} to ${sponsor.keyInfo.address}' - ${txid}`);
    }

    var waiting_for_funds = true;
    var client = new StackingClient(sponsors[sponsors.length-1].keyInfo.address, nodes[0]);
    while (waiting_for_funds) {
        let res = await client.getAccountBalance();
        waiting_for_funds = res.eqn(0);
        await sleep(5000);
    }

    round_robin = 0;
    let users = all_users.slice(0, NUMBER_OF_USERS);
    for (let user of users) {
        let index = round_robin % sponsors.length;
        let nonce = sponsors_nonces[index] as BN;
        let seeder = seeders[index];
        let amount = new BN(10000000);

        const txOptions: SignedTokenTransferOptions = {
            recipient: user.keyInfo.address,
            amount,
            senderKey: sponsors[index].keyInfo.privateKey,
            network: nodes[0],
            memo: 'tests ludo',
            nonce,
            fee: new BN(200),
        };

        sponsors_nonces[index] = nonce.addn(1);
        round_robin += 1;

        const transfer = await makeSTXTokenTransfer(txOptions);
        let txid = await broadcastTransaction(transfer, nodes[0]);
        sponsors_nonces.push(new BN(0));
        console.log(`TX '${sponsors[index].keyInfo.address} -> ${amount} to ${user.keyInfo.address}' - ${txid}`);
    }

    waiting_for_funds = true;
    client = new StackingClient(users[users.length-1].keyInfo.address, nodes[0]);
    while (waiting_for_funds) {
        let res = await client.getAccountBalance();
        waiting_for_funds = res.eqn(0);
        await sleep(5000);
    }

    round_robin = 0;
    for (let user of users) {
        let index = round_robin % nodes.length;
        let node = nodes[index];
        let salt = "0000";
        let name = user.keyInfo.address.toLowerCase();
        var sha256 = new shajs.sha256().update(`${name}.${namespace}${salt}`).digest();
        var hash160 = new ripemd160().update(sha256).digest('hex');
        var hashed_name = bufferCV(Buffer.from(hash160, "hex"))

        var contractCall = await makeContractCall({
            contractAddress: BNS_CONTRACT_ADDRESS,
            contractName: BNS_CONTRACT_NAME,
            functionName: "name-preorder",
            functionArgs: [hashed_name, uintCV(10000)],
            senderKey: user.keyInfo.privateKey,
            fee,
            nonce: new BN(0),
            network: nodes[0],
            postConditionMode: PostConditionMode.Allow,
            anchorMode: AnchorMode.OnChainOnly
        });
        
        var txid = await broadcastTransaction(contractCall, node);
        console.log(`TX 'name-preorder(${name})' broadcasted ${txid}`)

        let attachment = `${name}@${namespace}`;
        sha256 = new shajs.sha256().update(attachment).digest();
        hash160 = new ripemd160().update(sha256).digest('hex');
        let attachment_hash = bufferCV(Buffer.from(hash160, "hex"))
        contractCall = await makeContractCall({
            contractAddress: BNS_CONTRACT_ADDRESS,
            contractName: BNS_CONTRACT_NAME,
            functionName: "name-register",
            functionArgs: [bufferCVFromString(namespace), bufferCVFromString(name), bufferCVFromString(salt), attachment_hash],
            senderKey: user.keyInfo.privateKey,
            fee,
            nonce: new BN(1),
            network: nodes[0],
            postConditionMode: PostConditionMode.Allow,
            anchorMode: AnchorMode.OnChainOnly
        });
        
        txid = await broadcastTransaction(contractCall, node, Buffer.from(attachment, 'utf8'));
        console.log(`TX 'name-register(${name})' broadcasted ${txid} on ${node.coreApiUrl}`)
        round_robin += 1;
    }
})

function sleep(ms: number) { return new Promise(res => setTimeout(res, ms)); }
