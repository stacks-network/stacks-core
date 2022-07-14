import { Clarinet, Tx, Chain, Account, Contract, types } from 'https://deno.land/x/clarinet@v0.31.0/index.ts';
import { assertEquals } from "https://deno.land/std@0.90.0/testing/asserts.ts";
import { createHash } from "https://deno.land/std@0.107.0/hash/mod.ts";

const ERR_SIGNER_APPEARS_TWICE = 101;
const ERR_NOT_ENOUGH_SIGNERS = 102;
const ERR_INVALID_SIGNATURE = 103;
const ERR_UNAUTHORIZED_CONTRACT_CALLER = 104;
const ERR_MINER_ALREADY_SET = 105;

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

        //  to generate: stacks-inspect secp256k1-sign e2f4d0b1eca5f1b4eb853cd7f1c843540cfb21de8bfdaa59c504a6775cd2cfe9 7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101
        let signatorySigned    = "0xac04279c1a6fa31e87d6ee54790c4016a7c8b90587d9c71938b4f4eae2d448280435ebb9b9b7462e54d6eff23350aa8272e8d9f8f02332883dd845c14c19d5c300";
        //  to generate: stacks-inspect secp256k1-sign e2f4d0b1eca5f1b4eb853cd7f1c843540cfb21de8bfdaa59c504a6775cd2cfe9 003f8c631e98bf52b8dfa36f02df0aaab85dfefc5d8bedb41bc5184afdc4a16001
        let nonSignatorySigned = "0xee504bc280ff1564195638ed2d86e74994c75833432dff9be56a0880c0e52b146582a0b46fbda9640f32e2fc44a6cd1521ea2ef4816d2b1a48a36bb70f1b37fd00";
        let badSignature       = "0x0ca28913fe5d08da93f4738cee281747b00a76d6e1d266bcfa17d87b9542e0c979a3065dff06518bbd7d5d08059be79a41e3d5a74f39738bf1183f56091e5d7c01";

        const id_header_hash_1 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        let block = chain.mineBlock([
          // Successfully commit block with alice and signatory as the miners
          Tx.contractCall("multi-miner", "commit-block",
                [
                    types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                  "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                  "target-tip": id_header_hash_1 }),
                    types.list([signatorySigned]),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        const id_header_hash_2 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();

        block = chain.mineBlock([
            // Fail to commit block with alice and nonSignatory as the miners
            Tx.contractCall("multi-miner", "commit-block",
                [
                    types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                  "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                  "target-tip": id_header_hash_2 }),
                    types.list([nonSignatorySigned]),
                ],
                alice.address),
            // Fail to commit block with a bad signature
            Tx.contractCall("multi-miner", "commit-block",
                [
                    types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                  "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                  "target-tip": id_header_hash_2 }),
                    types.list([badSignature]),
                ],
                alice.address),
            // Fail to commit block with non-unique signers
            Tx.contractCall("multi-miner", "commit-block",
                [
                    types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                  "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                  "target-tip": id_header_hash_2 }),
                    types.list([signatorySigned, signatorySigned]),
                ],
                alice.address),
            // Fail to commit block with not-enough signers when sender isn't a miner
            Tx.contractCall("multi-miner", "commit-block",
                [
                    types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                  "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                  "target-tip": id_header_hash_2 }),
                    types.list([signatorySigned]),
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
                    types.principal(signatory1.address),
                    types.principal(signatory2.address),
                ])
            ],
            alice.address),
        ]);

        //  to generate: stacks-inspect secp256k1-sign e2f4d0b1eca5f1b4eb853cd7f1c843540cfb21de8bfdaa59c504a6775cd2cfe9 7deca54bdb555e4d9aa2310cb9ed8829d59e2098cbc06f62238cdd8fcb08c08101
        let signatory1Signed = "0xac04279c1a6fa31e87d6ee54790c4016a7c8b90587d9c71938b4f4eae2d448280435ebb9b9b7462e54d6eff23350aa8272e8d9f8f02332883dd845c14c19d5c300";
        //  to generate: stacks-inspect secp256k1-sign e2f4d0b1eca5f1b4eb853cd7f1c843540cfb21de8bfdaa59c504a6775cd2cfe9 003f8c631e98bf52b8dfa36f02df0aaab85dfefc5d8bedb41bc5184afdc4a16001
        let signatory2Signed = "0xee504bc280ff1564195638ed2d86e74994c75833432dff9be56a0880c0e52b146582a0b46fbda9640f32e2fc44a6cd1521ea2ef4816d2b1a48a36bb70f1b37fd00";
        let badSignature     = "0x0ca28913fe5d08da93f4738cee281747b00a76d6e1d266bcfa17d87b9542e0c979a3065dff06518bbd7d5d08059be79a41e3d5a74f39738bf1183f56091e5d7c01";

        let id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();

        let block = chain.mineBlock([
          // Successfully commit block with alice as a sender and signatory1/2 as the miners
          Tx.contractCall("multi-miner", "commit-block",
                [
                    types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                  "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                  "target-tip": id_header_hash }),
                    types.list([signatory1Signed, signatory2Signed]),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            // Successfully commit block with bob as a sender and signatory1/2 as the miners
            Tx.contractCall("multi-miner", "commit-block",
                    [
                        types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                      "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                      "target-tip": id_header_hash }),
                        types.list([signatory1Signed, signatory2Signed]),
                    ],
                    bob.address),
            ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // now test failure modes
        id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            // Fail to commit block with alice and signatory as the miners
            Tx.contractCall("multi-miner", "commit-block",
                [
                    types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                  "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                  "target-tip": id_header_hash }),
                    types.list([signatory1Signed]),
                ],
                alice.address),
            // Fail to commit block with non-unique signers
            Tx.contractCall("multi-miner", "commit-block",
                [
                    types.tuple({ "block": types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                                  "withdrawal-root": types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                                  "target-tip": id_header_hash }),
                    types.list([signatory1Signed, signatory2Signed]),
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
