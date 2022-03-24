import { Clarinet, Tx, Chain, Account, Contract, types } from 'https://deno.land/x/clarinet@v0.16.0/index.ts';
import { assertEquals } from "https://deno.land/std@0.90.0/testing/asserts.ts";
import { createHash } from "https://deno.land/std@0.107.0/hash/mod.ts";

Clarinet.test({
    name: "Ensure that block can be committed by subnet miner",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // valid miner
        const alice = accounts.get("wallet_1")!;
        // invalid miner
        const bob = accounts.get("wallet_2")!;
        const charlie = accounts.get("wallet_3")!;

        // Successfully commit block at height 0 with alice.
        let block = chain.mineBlock([
            Tx.contractCall("subnets", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    types.uint(0),
                ],
                alice.address),
        ]);
        assertEquals(block.height, 2);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));


        // Try and fail to commit a different block, but again at height 0.
        block = chain.mineBlock([
            Tx.contractCall("subnets", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    types.uint(0),
                ],
                alice.address),
        ]);
        assertEquals(block.height, 3);
        block.receipts[0].result
            .expectErr()
            .expectInt(3);


        // Try and fail to commit a block at height 1 with an invalid miner.
        block = chain.mineBlock([
            Tx.contractCall("subnets", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    types.uint(1),
                ],
                bob.address),
        ]);
        assertEquals(block.height, 4);
        block.receipts[0].result
            .expectErr()
            .expectInt(3);

        // Successfully commit block at height 1 with valid miner.
        block = chain.mineBlock([
            Tx.contractCall("subnets", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    types.uint(1),
                ],
                alice.address),
        ]);
        assertEquals(block.height, 5);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 2, 2, 2, 2]));
    },
});


Clarinet.test({
    name: "Ensure that user can deposit NFT & miner can withdraw it",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // valid miner
        const alice = accounts.get("wallet_1")!;
        // invalid miner
        const bob = accounts.get("wallet_2")!;
        // user
        const charlie = accounts.get("wallet_3")!;

        // nft contract id
        const nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-nft")!;

        // User should be able to mint an NFT
        let block = chain.mineBlock([
            Tx.contractCall("simple-nft", "test-mint", [types.principal(charlie.address)], charlie.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);

        // User should be able to deposit NFT asset
        block = chain.mineBlock([
            Tx.contractCall("subnets", "deposit-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                ],
                charlie.address),
        ]);
        assertEquals(block.height, 3);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should not be able to deposit an NFT asset they don't own
        block = chain.mineBlock([
            Tx.contractCall("subnets", "deposit-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(4);

        // User should not be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("subnets", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(bob.address),
                    types.principal(nft_contract.contract_id),
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(2);

        // Miner should be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("subnets", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(bob.address),
                    types.principal(nft_contract.contract_id),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);


        // Miner should not be able to withdraw NFT asset a second time
        block = chain.mineBlock([
            Tx.contractCall("subnets", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(bob.address),
                    types.principal(nft_contract.contract_id),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(4);

    },
});
