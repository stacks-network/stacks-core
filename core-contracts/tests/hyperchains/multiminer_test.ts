import { Clarinet, Tx, Chain, Account, Contract, types } from 'https://deno.land/x/clarinet@v0.31.0/index.ts';
import { assertEquals } from "https://deno.land/std@0.90.0/testing/asserts.ts";
import { createHash } from "https://deno.land/std@0.107.0/hash/mod.ts";
import { decode as decHex, encode as encHex } from "https://deno.land/std@0.149.0/encoding/hex.ts";
// import * as secp from "https://deno.land/x/secp256k1@1.6.3/mod.ts";

const ERR_SIGNER_APPEARS_TWICE = 101;
const ERR_NOT_ENOUGH_SIGNERS = 102;
const ERR_INVALID_SIGNATURE = 103;
const ERR_UNAUTHORIZED_CONTRACT_CALLER = 104;
const ERR_MINER_ALREADY_SET = 105;

function fromHex(input: string) {
    const hexBytes = new TextEncoder().encode(input);
    return decHex(hexBytes);
}

function toHex(input: Uint8Array) {
    const hexBytes = encHex(input);
    return new TextDecoder().decode(hexBytes);
}

function buffFromHex(input: string) {
    return types.buff(fromHex(input));
}

// function sign(messageHash: string, signer: string) {
//     const result = secp.signSync(messageHash, signer.slice(0, -2), { der: false, recovered: true });
//     return `0x${toHex(result[0])}0${result[1]}`
// }


function sign(messageHash: string, signer: string) {
    const signature_map = new Map<string, string>();
    signature_map.set('(7acbdb54d0798e8b2930a0b2adeea24e46813edadd04f3497f020f328c77dbb2, 7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101)', '0xea418d4ae220a5c4afdc0c8e21c28e26a338117fee39f878ebb1251c56f74ac3da64b20e66fca8b697a9751ba0599ba2a5210add0f7a43e5c2a230d3f4df051600');
    signature_map.set('(63ba42b8727b1f01d78de3b7bfad61d6f3b146695350457e1dbb252861135461, 003f8c631e98bf52b8dfa36f02df0aaab85dfefc5d8bedb41bc5184afdc4a16001)', '0xb459af09a1d6200766e32f4513392da7ffd374b6ba925a41c26854c5e02c7623ec419b4f68eae501f36fccfd9a40c83489f232446ae6dc04c075efc17b5b6eaa00');
    signature_map.set('(63ba42b8727b1f01d78de3b7bfad61d6f3b146695350457e1dbb252861135461, 7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101)', '0x9874cae8caf04ac52bf0af74c79edd58f81164d78245e2e197d2832b60e0921b3dff0430720b725956df91672eab183b85402c164a6819eb7ac0a0850a1d21f801');
    signature_map.set('(822caf4a720c0d1db92bb948521650dbeabe5fa94b5817f718d6e4a715d2b583, 7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101)', '0x549f505da94df6f56df8da10eb2b5585a95ceca2ca3a6168176840215a330c5825ab16f6eb8b48474006f9eb2ce3fd61a5552ccb53755aaccdee1c0fbc6fcb8e01');
    signature_map.set('(822caf4a720c0d1db92bb948521650dbeabe5fa94b5817f718d6e4a715d2b583, 003f8c631e98bf52b8dfa36f02df0aaab85dfefc5d8bedb41bc5184afdc4a16001)', '0xc223b412c0e2ae1dc28c981b23de7d8a601c94cc190e7e37227ecd47fe4be8a628394f826cb8a25c133a599ef2fc3796155c5ecc924cbc35fff4ab6a0cc685ff01');
    signature_map.set('(cad85aa65df028d53b32303c7c1204b660102319720295cd3cc3fd71553fe217, 7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101)', '0xc8ee11648c48ae85f1b8003c53690efc9aab20ce05526643fb0ccc3f2ac46cee174c51ba62f5e06cc5223cee0efccb7c1eec20e1fe22bb6654daab78e067f16a00');
    signature_map.set('(cad85aa65df028d53b32303c7c1204b660102319720295cd3cc3fd71553fe217, 7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101)', '0xc8ee11648c48ae85f1b8003c53690efc9aab20ce05526643fb0ccc3f2ac46cee174c51ba62f5e06cc5223cee0efccb7c1eec20e1fe22bb6654daab78e067f16a00');    
    signature_map.set('(cad85aa65df028d53b32303c7c1204b660102319720295cd3cc3fd71553fe217, 003f8c631e98bf52b8dfa36f02df0aaab85dfefc5d8bedb41bc5184afdc4a16001)', '0x7090b64cc6c63fe675de25d0c890bbac58e5ca93e9bd2c9c40a05229ef464fae6232490c2d8c66565a22a97d2155aa2d12b6434e8ba75c081e11b9f9d9a4ef7500');
    signature_map.set('(84b70510646b9b5967d637fca9fd9cf29d957848d52577348d09ca59432a867a, 7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101)', '0x11796554ddafc42d3aae1738ee1ddf573988404d5c990c574cbdefb73d31b8995e54abcda499738aaeffb6432fe37f1c2bc749471a3815fea131eb4ba76da14c00');
    signature_map.set('(84b70510646b9b5967d637fca9fd9cf29d957848d52577348d09ca59432a867a, 003f8c631e98bf52b8dfa36f02df0aaab85dfefc5d8bedb41bc5184afdc4a16001)', '0xf34be14d6411debab873c0a79033d4a4a6e39a8acb46eb214d2ac112148698011a62abf466cc3fbb2b5f7e144c631abd86547c3a0763675315bad32531e8084e01');

    const key = `(${messageHash}, ${signer})`;
    if (signature_map.has(key)) {
        return signature_map.get(key)!;
    } else {
        console.log(`sign("${messageHash}", "${signer}")`);
        throw "No known signature for request";
    }
}

Clarinet.test({
    name: "Test multi-party commit when one party submits transactions and other party is signatory",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        // todo: is there a way to get this ID from Clarinet?
        const multi_miner_contract = Array.from(contracts.keys()).find( x => x.endsWith("multi-miner") )!;
        // valid miner
        const alice = accounts.get("wallet_1")!;
        // invalid miner
        const bob = accounts.get("wallet_2")!;

        const signatory = { 
            secretKey: "7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101",
            publicKey: "024b81bd729820749bdf59a62860bed0f87f44659d502fee9b9321de3dd0a00437",
            address: "ST2CVT7B6KVWEVYQPZ2ZS3H9E4G20146PQQ4NF9ED"
        };

        const nonSignatory = { 
            secretKey: "003f8c631e98bf52b8dfa36f02df0aaab85dfefc5d8bedb41bc5184afdc4a16001",
            publicKey: "0294cf0f56b638b2d38c39a92a90692c7ed4eb980832d8dca33cacfeb80c3f2741",
            address: "STECHMJGSBWNGW3MS334R3PHQD4F59EFMAXY7Y7F"
        };

        // set the multi_miner_contract as the miner of the hyperchains contract
        //  and set alice and signatory as miners in the multi-miner contract
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(multi_miner_contract),
            ],
            alice.address),
            Tx.contractCall("multi-miner", "set-miners",
            [
                types.list([
                    types.principal(alice.address),
                    types.principal(signatory.address),
                ])
            ],
            alice.address),
        ]);

        const block_hash_1 = "0x0000000000000001000000000000000100000000000000010000000000000001";
        const withdrawal_root_1 = "0x0000000000000001000000000000000100000000000000010000000000000002";

        const id_header_hash_1 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        const commit_data_1 = types.tuple({ 
            "block": buffFromHex(block_hash_1.slice(2)),
            "withdrawal-root": buffFromHex(withdrawal_root_1.slice(2)),
            "target-tip": id_header_hash_1
        });
        const message_hash_1 = chain.callReadOnlyFn('multi-miner', 'make-block-commit-hash', [commit_data_1], alice.address).result.toString();
        const signatory_signed_1 = sign(message_hash_1.slice(2), signatory.secretKey);

        let block = chain.mineBlock([
          // Successfully commit block with alice and signatory as the miners
          Tx.contractCall("multi-miner", "commit-block",
                [
                    commit_data_1,
                    types.list([signatory_signed_1]),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(fromHex(block_hash_1.slice(2)));

        const id_header_hash_2 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        const commit_data_2 = types.tuple({ 
            "block": buffFromHex(block_hash_1.slice(2)),
            "withdrawal-root": buffFromHex(withdrawal_root_1.slice(2)),
            "target-tip": id_header_hash_2
        });
        const message_hash_2 = chain.callReadOnlyFn('multi-miner', 'make-block-commit-hash', [commit_data_2], alice.address).result.toString();
        const non_signatory_signed_2 = sign(message_hash_2.slice(2), nonSignatory.secretKey);
        const signatory_signed_2 = sign(message_hash_2.slice(2), signatory.secretKey);
        // provide a totally invalid signature
        const bad_signature_1 = "0x500f511da88df8856d77da10eb2ff585a95cecddca3a6ee817aa40215a330c5825ab16f6eb8b48474006f9eb2ce3fd61a5552ccb53755aaccdee1c0fbc6fcb8e88";
        // sign the wrong hash
        const bad_signature_2 = sign(message_hash_1.slice(2), signatory.secretKey);

        block = chain.mineBlock([
            // Fail to commit block with alice and nonSignatory as the miners
            Tx.contractCall("multi-miner", "commit-block",
                [
                    commit_data_2,
                    types.list([non_signatory_signed_2]),
                ],
                alice.address),
            // Fail to commit block with a bad signature
            Tx.contractCall("multi-miner", "commit-block",
                [
                    commit_data_2,
                    types.list([bad_signature_1]),
                ],
                alice.address),
            // Fail to commit block with non-unique signers
            Tx.contractCall("multi-miner", "commit-block",
                [
                    commit_data_2,
                    types.list([signatory_signed_2, signatory_signed_2]),
                ],
                alice.address),
            // Fail to commit block with not-enough signers when sender isn't a miner
            Tx.contractCall("multi-miner", "commit-block",
                [
                    commit_data_2,
                    types.list([signatory_signed_2]),
                ],
                bob.address),
        ]);

        block.receipts[0].result
            .expectErr()
            .expectInt(ERR_NOT_ENOUGH_SIGNERS);
        block.receipts[1].result
            .expectErr()
            .expectInt(ERR_INVALID_SIGNATURE);
        block.receipts[2].result
            .expectErr()
            .expectInt(ERR_SIGNER_APPEARS_TWICE);
        block.receipts[3].result
            .expectErr()
            .expectInt(ERR_NOT_ENOUGH_SIGNERS);
    },
});

Clarinet.test({
    name: "Test multi-party commit when 2 parties are signatories",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        // todo: is there a way to get this ID from Clarinet?
        const multi_miner_contract = Array.from(contracts.keys()).find( x => x.endsWith("multi-miner") )!;
        // both alice and bob are invalid miners
        const alice = accounts.get("wallet_1")!;
        const bob = accounts.get("wallet_2")!;


        const signatory1 = { 
            secretKey: "7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101",
            publicKey: "024b81bd729820749bdf59a62860bed0f87f44659d502fee9b9321de3dd0a00437",
            address: "ST2CVT7B6KVWEVYQPZ2ZS3H9E4G20146PQQ4NF9ED"
        };

        const signatory2 = { 
            secretKey: "003f8c631e98bf52b8dfa36f02df0aaab85dfefc5d8bedb41bc5184afdc4a16001",
            publicKey: "0294cf0f56b638b2d38c39a92a90692c7ed4eb980832d8dca33cacfeb80c3f2741",
            address: "STECHMJGSBWNGW3MS334R3PHQD4F59EFMAXY7Y7F"
        };

        // set the multi_miner_contract as the miner of the hyperchains contract
        //  and set signatory1 and signatory2 as miners in the multi-miner contract
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(multi_miner_contract),
            ],
            alice.address),
            Tx.contractCall("multi-miner", "set-miners",
            [
                types.list([
                    types.principal(signatory1.address),
                    types.principal(signatory2.address),
                ])
            ],
            alice.address),
        ]);

        const block_hash_1 = "0x0000000200000001000000000000000100000000000000010000000000000001";
        const withdrawal_root_1 = "0x0000000000000001000000000000000100000000400000010000000000000002";


        const id_header_hash_1 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        const commit_data_1 = types.tuple({ 
            "block": buffFromHex(block_hash_1.slice(2)),
            "withdrawal-root": buffFromHex(withdrawal_root_1.slice(2)),
            "target-tip": id_header_hash_1
        });
        const message_hash_1 = chain.callReadOnlyFn('multi-miner', 'make-block-commit-hash', [commit_data_1], alice.address).result.toString();
        const signatory1_sig_1 = sign(message_hash_1.slice(2), signatory1.secretKey);
        const signatory2_sig_1 = sign(message_hash_1.slice(2), signatory2.secretKey);

        let block = chain.mineBlock([
          // Successfully commit block with alice as a sender and signatory1/2 as the miners
          Tx.contractCall("multi-miner", "commit-block",
                [
                    commit_data_1,
                    types.list([signatory2_sig_1, signatory1_sig_1]),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(fromHex(block_hash_1.slice(2)));

        const id_header_hash_2 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        const commit_data_2 = types.tuple({ 
            "block": buffFromHex(block_hash_1.slice(2)),
            "withdrawal-root": buffFromHex(withdrawal_root_1.slice(2)),
            "target-tip": id_header_hash_2
        });
        const message_hash_2 = chain.callReadOnlyFn('multi-miner', 'make-block-commit-hash', [commit_data_2], alice.address).result.toString()
        const signatory1_sig_2 = sign(message_hash_2.slice(2), signatory1.secretKey);
        const signatory2_sig_2 = sign(message_hash_2.slice(2), signatory2.secretKey);

        block = chain.mineBlock([
            // Successfully commit block with bob as a sender and signatory1/2 as the miners
            Tx.contractCall("multi-miner", "commit-block",
                    [
                        commit_data_2,
                        types.list([signatory1_sig_2, signatory2_sig_2]),
                    ],
                    bob.address),
            ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(fromHex(block_hash_1.slice(2)));

        // now test failure modes
        const id_header_hash_3 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        const commit_data_3 = types.tuple({ 
            "block": buffFromHex(block_hash_1.slice(2)),
            "withdrawal-root": buffFromHex(withdrawal_root_1.slice(2)),
            "target-tip": id_header_hash_3
        });
        const message_hash_3 = chain.callReadOnlyFn('multi-miner', 'make-block-commit-hash', [commit_data_3], alice.address).result.toString();
        const signatory1_sig_3 = sign(message_hash_3.slice(2), signatory1.secretKey);
        const signatory2_sig_3 = sign(message_hash_3.slice(2), signatory2.secretKey);

        block = chain.mineBlock([
            // Fail to commit block with alice and signatory as the miners
            Tx.contractCall("multi-miner", "commit-block",
                [
                    commit_data_3,
                    types.list([signatory2_sig_3]),
                ],
                alice.address),
            // Fail to commit block with non-unique signers
            Tx.contractCall("multi-miner", "commit-block",
                [
                    commit_data_3,
                    types.list([signatory1_sig_3, signatory2_sig_3]),
                ],
                signatory1.address),
        ]);

        block.receipts[0].result
            .expectErr()
            .expectInt(ERR_NOT_ENOUGH_SIGNERS);
        block.receipts[1].result
            .expectErr()
            .expectInt(ERR_SIGNER_APPEARS_TWICE);
    },
});
