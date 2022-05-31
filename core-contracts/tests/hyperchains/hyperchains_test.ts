import { Clarinet, Tx, Chain, Account, Contract, types } from 'https://deno.land/x/clarinet@v0.31.0/index.ts';
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

        let block = chain.mineBlock([
          // Successfully commit block at height 0 with alice.
          Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                ],
                alice.address),
          // Try and fail to commit a different block, but again at height 0.
          Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    types.buff(new Uint8Array([0, 2, 2, 2, 3])),
                ],
                alice.address),
        ]);
        assertEquals(block.height, 2);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));
        // should return (err ERR_BLOCK_ALREADY_COMMITTED)
        block.receipts[1].result
            .expectErr()
            .expectInt(1);


        // Try and fail to commit a block at height 1 with an invalid miner.
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    types.buff(new Uint8Array([0, 2, 2, 2, 3])),
                ],
                bob.address),
        ]);
        assertEquals(block.height, 3);
        // should return (err ERR_BLOCK_ALREADY_COMMITTED)
        block.receipts[0].result
            .expectErr()
            .expectInt(2);

        // Successfully commit block at height 1 with valid miner.
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    types.buff(new Uint8Array([0, 2, 2, 2, 3])),
                ],
                alice.address),
        ]);
        assertEquals(block.height, 4);
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
        const hyperchain_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.hyperchains")!;

        // User should be able to mint an NFT
        let block = chain.mineBlock([
            Tx.contractCall("simple-nft", "test-mint", [types.principal(charlie.address)], charlie.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);
        // Check that user owns NFT
        let assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        let nft_amount = assets[charlie.address];
        assertEquals(nft_amount, 1);

        // User should not be able to deposit NFT asset before miner allows the asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                    types.principal(nft_contract.contract_id),
                ],
                charlie.address),
        ]);
        // should return (err ERR_DISALLOWED_ASSET)
        block.receipts[0].result
            .expectErr()
            .expectInt(5);

        // Invalid miner can't setup allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                bob.address),
        ]);
        // should return (err ERR_INVALID_MINER)
        block.receipts[0].result
            .expectErr()
            .expectInt(2);

        // Miner sets up allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should be able to deposit NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                    types.principal(nft_contract.contract_id),
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);
        // Check that contract owns NFT, and that the user does not
        assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        nft_amount = assets[charlie.address];
        assertEquals(nft_amount, 0);
        nft_amount = assets[hyperchain_contract.contract_id];
        assertEquals(nft_amount, 1);

        // User should not be able to deposit an NFT asset they don't own
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                    types.principal(nft_contract.contract_id),
                ],
                charlie.address),
        ]);
        // should return (err ERR_CONTRACT_CALL_FAILED)
        block.receipts[0].result
            .expectErr()
            .expectInt(3);

        let root_hash = new Uint8Array([203, 225, 170, 121, 99, 143, 221, 118, 153, 59, 252, 68, 117, 30, 27, 33, 49, 100, 166, 167, 250, 154, 172, 149, 149, 79, 236, 105, 254, 184, 172, 103]);
        // Miner should commit a block with the appropriate root hash
        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        assertEquals(block.height, 8);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        let nft_sib_hash = new Uint8Array([33, 202, 115, 15, 237, 187, 156, 88, 59, 212, 42, 195, 30, 149, 130, 0, 37, 203, 93, 165, 189, 33, 107, 213, 116, 211, 170, 0, 89, 231, 154, 3]);
        let nft_leaf_hash = new Uint8Array([38, 72, 158, 13, 57, 120, 9, 95, 13, 62, 11, 118, 71, 237, 60, 173, 121, 221, 127, 38, 163, 75, 203, 191, 227, 4, 195, 17, 239, 76, 42, 55]);
        // User should be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])

                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check that user owns NFT
        assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        nft_amount = assets[charlie.address];
        assertEquals(nft_amount, 1);


        // User should not be able to withdraw NFT asset a second time
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])

                ],
                charlie.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

    },
});


Clarinet.test({
    name: "Ensure that user can deposit FT & miner can withdraw it",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // valid miner
        const alice = accounts.get("wallet_1")!;
        // invalid miner
        const bob = accounts.get("wallet_2")!;
        // user
        const charlie = accounts.get("wallet_3")!;

        // ft contract
        const ft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-ft")!;

        // User should be able to mint a fungible token
        let block = chain.mineBlock([
            Tx.contractCall("simple-ft", "gift-tokens", [types.principal(charlie.address)], charlie.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);
        // User should be able to mint another fungible token
        block = chain.mineBlock([
            Tx.contractCall("simple-ft", "gift-tokens", [types.principal(charlie.address)], charlie.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);

        // User should not be able to deposit FT assets if they are not allowed
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-ft-asset",
                [
                    types.uint(2),
                    types.principal(charlie.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.principal(ft_contract.contract_id),
                ],
                charlie.address),
        ]);
        // should return (err ERR_DISALLOWED_ASSET)
        block.receipts[0].result
            .expectErr()
            .expectInt(5);

        // Invalid miner can't setup allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                bob.address),
        ]);
        // should return (err ERR_INVALID_MINER)
        block.receipts[0].result
            .expectErr()
            .expectInt(2);

        // Miner sets up allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should not be able to deposit a larger quantity than they own
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-ft-asset",
                [
                    types.uint(3),
                    types.principal(charlie.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.principal(ft_contract.contract_id),
                ],
                charlie.address),
        ]);
        // should return (err ERR_CONTRACT_CALL_FAILED)
        block.receipts[0].result
            .expectErr()
            .expectInt(3);

        // User should be able to deposit FT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-ft-asset",
                [
                    types.uint(2),
                    types.principal(charlie.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.principal(ft_contract.contract_id),
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should not be able to deposit an FT asset they don't own
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-ft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.principal(ft_contract.contract_id),
                ],
                charlie.address),
        ]);
        // should return (err ERR_CONTRACT_CALL_FAILED)
        block.receipts[0].result
            .expectErr()
            .expectInt(3);

        let root_hash = new Uint8Array([203, 225, 170, 121, 99, 143, 221, 118, 153, 59, 252, 68, 117, 30, 27, 33, 49, 100, 166, 167, 250, 154, 172, 149, 149, 79, 236, 105, 254, 184, 172, 103]);
        // Miner should commit a block with the appropriate root hash
        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        assertEquals(block.height, 10);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        let ft_leaf_hash = new Uint8Array([33, 202, 115, 15, 237, 187, 156, 88, 59, 212, 42, 195, 30, 149, 130, 0, 37, 203, 93, 165, 189, 33, 107, 213, 116, 211, 170, 0, 89, 231, 154, 3]);
        let ft_sib_hash = new Uint8Array([38, 72, 158, 13, 57, 120, 9, 95, 13, 62, 11, 118, 71, 237, 60, 173, 121, 221, 127, 38, 163, 75, 203, 191, 227, 4, 195, 17, 239, 76, 42, 55]);
        // User should be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(ft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(ft_sib_hash),
                        "is-left-side": types.bool(false)
                    })])

                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check that user owns NFT
        let assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        let ft_amount = assets[charlie.address];
        assertEquals(ft_amount, 1);

        // User should not be able to withdraw NFT asset a second time
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(ft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(ft_sib_hash),
                        "is-left-side": types.bool(false)
                    })])

                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

    },
});
