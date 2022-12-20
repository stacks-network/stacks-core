import { Clarinet, Tx, Chain, Account, Contract, types } from 'https://deno.land/x/clarinet@v1.2.0/index.ts';
import { assertEquals } from "https://deno.land/std@0.90.0/testing/asserts.ts";
import { createHash } from "https://deno.land/std@0.107.0/hash/mod.ts";
import { decode as decHex, encode as encHex } from "https://deno.land/std@0.149.0/encoding/hex.ts";
import * as secp from "https://deno.land/x/secp256k1@1.6.3/mod.ts";

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

// Once Clarinet supports deno import maps, uncomment this and remove the other
// sign function so that the tests do not need to hardcode a signature map.
//
function sign(messageHash: string, signer: string) {
    const result = secp.signSync(messageHash, signer.slice(0, -2), { der: false, recovered: true });
    return `0x${toHex(result[0])}0${result[1]}`
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
