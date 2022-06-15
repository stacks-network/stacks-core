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

        const id_header_hash1 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();

        let block = chain.mineBlock([
          // Successfully commit block at height 0 with alice.
          Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash1,
                    types.buff(new Uint8Array([0, 1, 1, 1, 2])),
                ],
                alice.address),
          // Try and fail to commit a different block, but again at height 0.
          Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    id_header_hash1,
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
        const id_header_hash2 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    id_header_hash2,
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
        const id_header_hash3 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                    id_header_hash3,
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
        const id_header_hash1 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash1,
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
        const id_header_hash1 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash1,
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
        // User should be able to withdraw FT asset
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

        // Check that user owns FT
        let assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        let ft_amount = assets[charlie.address];
        assertEquals(ft_amount, 1);

        // User should not be able to withdraw FT asset a second time
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


Clarinet.test({
    name: "Ensure that withdrawals work with a more complex Merkle tree",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // valid miner
        const alice = accounts.get("wallet_1")!;
        // user
        const charlie = accounts.get("wallet_3")!;
        let charlie_init_balance = 100000000000000;

        // get address of contracts
        const ft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-ft")!;
        const nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-nft")!;

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
        // User should be able to mint an NFT
        block = chain.mineBlock([
            Tx.contractCall("simple-nft", "test-mint", [types.principal(charlie.address)], charlie.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);

        // Miner sets up allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check balances before deposits
        let stx_assets = chain.getAssetsMaps().assets["STX"];
        let stx_amount = stx_assets[charlie.address];
        assertEquals(stx_amount, charlie_init_balance);
        let ft_assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        let ft_amount = ft_assets[charlie.address];
        assertEquals(ft_amount, 2);
        let nft_assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        let nft_amount = nft_assets[charlie.address];
        assertEquals(nft_amount, 1);

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

        // User should be able to deposit STX
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-stx",
                [
                    types.uint(5),
                    types.principal(charlie.address),
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should be able to deposit NFT
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

        // Check balances after deposits
        stx_assets = chain.getAssetsMaps().assets["STX"];
        stx_amount = stx_assets[charlie.address];
        assertEquals(stx_amount, charlie_init_balance-5);
        ft_assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        ft_amount = ft_assets[charlie.address];
        assertEquals(ft_amount, 0);
        nft_assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        nft_amount = nft_assets[charlie.address];
        assertEquals(nft_amount, 0);


        // Here we are using the root hash that would be constructed for 3 withdrawal requests.
        // The data used for this can be seen in the test `test_verify_withdrawal_merkle_tree` in `withdrawal.rs`
        let root_hash = new Uint8Array([186, 138, 157, 125, 128, 50, 197, 200, 75, 139, 27, 104, 110, 157, 182, 49, 140, 62, 51, 70, 251, 139, 131, 82, 67, 53, 118, 168, 54, 239, 111, 30]);
        const id_header_hash1 = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash1,
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // User should be able to withdraw FT asset
        let ft_leaf_hash = new Uint8Array([168, 206, 151, 196, 231, 103, 99, 34, 213, 247, 225, 237, 184, 34, 243, 125, 125, 213, 140, 199, 41, 34, 35, 208, 125, 174, 10, 55, 139, 82, 34, 213]);
        let ft_level_one_sib_hash = new Uint8Array([166, 126, 56, 176, 32, 46, 181, 232, 203, 157, 163, 237, 42, 69, 2, 20, 196, 115, 199, 233, 214, 168, 217, 10, 100, 144, 59, 114, 68, 88, 116, 34]);
        let ft_level_two_sib_hash = new Uint8Array([125, 135, 145, 128, 20, 186, 79, 199, 225, 200, 112, 161, 40, 176, 202, 130, 69, 245, 254, 231, 47, 73, 129, 255, 238, 48, 165, 14, 175, 180, 192, 121]);
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
                        "hash": types.buff(ft_level_one_sib_hash),
                        "is-left-side": types.bool(true)
                    }),
                        types.tuple({
                        "hash": types.buff(ft_level_two_sib_hash),
                        "is-left-side": types.bool(false)
                    })])

                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should be able to withdraw STX
        let stx_leaf_hash = new Uint8Array([166, 126, 56, 176, 32, 46, 181, 232, 203, 157, 163, 237, 42, 69, 2, 20, 196, 115, 199, 233, 214, 168, 217, 10, 100, 144, 59, 114, 68, 88, 116, 34]);
        let stx_level_one_sib_hash = new Uint8Array([168, 206, 151, 196, 231, 103, 99, 34, 213, 247, 225, 237, 184, 34, 243, 125, 125, 213, 140, 199, 41, 34, 35, 208, 125, 174, 10, 55, 139, 82, 34, 213]);
        let stx_level_two_sib_hash = new Uint8Array([125, 135, 145, 128, 20, 186, 79, 199, 225, 200, 112, 161, 40, 176, 202, 130, 69, 245, 254, 231, 47, 73, 129, 255, 238, 48, 165, 14, 175, 180, 192, 121]);
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-stx",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.buff(root_hash),
                    types.buff(stx_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(stx_level_one_sib_hash),
                        "is-left-side": types.bool(false)
                    }),
                        types.tuple({
                            "hash": types.buff(stx_level_two_sib_hash),
                            "is-left-side": types.bool(false)
                        })])

                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should be able to withdraw NFT asset
        let nft_leaf_hash = new Uint8Array([8, 0, 211, 114, 10, 69, 44, 38, 38, 104, 140, 88, 105, 75, 97, 72, 218, 204, 55, 225, 59, 120, 37, 235, 204, 33, 229, 37, 45, 39, 75, 116]);
        let nft_level_one_sib_hash = new Uint8Array([8, 0, 211, 114, 10, 69, 44, 38, 38, 104, 140, 88, 105, 75, 97, 72, 218, 204, 55, 225, 59, 120, 37, 235, 204, 33, 229, 37, 45, 39, 75, 116]);
        let nft_level_two_sib_hash = new Uint8Array([94, 66, 211, 71, 239, 174, 90, 87, 146, 231, 42, 206, 116, 57, 31, 8, 128, 148, 191, 242, 102, 223, 86, 35, 241, 182, 144, 23, 12, 76, 40, 102]);
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_level_one_sib_hash),
                        "is-left-side": types.bool(true)
                    }), types.tuple({
                        "hash": types.buff(nft_level_two_sib_hash),
                        "is-left-side": types.bool(true)
                    })
                    ])

                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check balances after withdrawals
        stx_assets = chain.getAssetsMaps().assets["STX"];
        stx_amount = stx_assets[charlie.address];
        assertEquals(stx_amount, charlie_init_balance-4);
        ft_assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        ft_amount = ft_assets[charlie.address];
        assertEquals(ft_amount, 1);
        nft_assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        nft_amount = nft_assets[charlie.address];
        assertEquals(nft_amount, 1);

        // For safety, check that user can't withdraw FT asset a second time with same key
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
                        "hash": types.buff(ft_level_one_sib_hash),
                        "is-left-side": types.bool(true)
                    }),
                        types.tuple({
                            "hash": types.buff(ft_level_two_sib_hash),
                            "is-left-side": types.bool(false)
                    })])

                ],
                charlie.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

        // For safety, check that user can't withdraw STX asset a second time with same key
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-stx",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.buff(root_hash),
                    types.buff(stx_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(stx_level_one_sib_hash),
                        "is-left-side": types.bool(false)
                    }),
                        types.tuple({
                            "hash": types.buff(stx_level_two_sib_hash),
                            "is-left-side": types.bool(false)
                        })])

                ],
                charlie.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

        // For safety, check that user can't withdraw NFT asset a second time with same key
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_level_one_sib_hash),
                        "is-left-side": types.bool(true)
                    }), types.tuple({
                        "hash": types.buff(nft_level_two_sib_hash),
                        "is-left-side": types.bool(true)
                    })
                    ])

                ],
                charlie.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

    },
});
