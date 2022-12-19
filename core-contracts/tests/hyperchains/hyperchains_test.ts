import { Clarinet, Tx, Chain, Account, Contract, types } from 'https://deno.land/x/clarinet@v1.2.0/index.ts';
import { assertEquals } from "https://deno.land/std@0.90.0/testing/asserts.ts";

import { decode as decHex, encode as encHex } from "https://deno.land/std@0.149.0/encoding/hex.ts";

function fromHex(input: string) {
    const hexBytes = new TextEncoder().encode(input);
    return decHex(hexBytes);
}

Clarinet.test({
   name: "Unit test the withdrawal leaf hash calculations using test vectors", 
   async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        const alice = accounts.get("wallet_1")!.address;
        // Test data comes from clarity_vm::withdrawal tests
        const block_height = 0;
        const recipient = "ST18F1AHKW194BWQ3CEFDPWVRARA79RBGFEWSDQR8";
        const leaf_hash_1 = chain.callReadOnlyFn('hyperchains', 'leaf-hash-withdraw-stx', [
            types.uint(1),
            types.principal(recipient),
            types.uint(0),
            types.uint(block_height),
        ], alice).result.toString();
        assertEquals(leaf_hash_1, "0xbde3658bbc38952599ef925ea3075a2fbfc5619cebf48cce140994c8b328fe35");

        const ft_contract = "ST18F1AHKW194BWQ3CEFDPWVRARA79RBGFEWSDQR8.simple-ft";
        const nft_contract = "ST18F1AHKW194BWQ3CEFDPWVRARA79RBGFEWSDQR8.simple-nft";

        const leaf_hash_2 = chain.callReadOnlyFn('hyperchains', 'leaf-hash-withdraw-ft', [
            types.principal(ft_contract),
            types.uint(1),
            types.principal(recipient),
            types.uint(1),
            types.uint(block_height),
        ], alice).result.toString();
        assertEquals(leaf_hash_2, "0x33dcd4279c21663c457927c300fe58e415e518b34e6ae90018d536cc69cda811");

        const leaf_hash_3 = chain.callReadOnlyFn('hyperchains', 'leaf-hash-withdraw-nft', [
            types.principal(nft_contract),
            types.uint(1),
            types.principal(recipient),
            types.uint(2),
            types.uint(block_height),
        ], alice).result.toString();
        assertEquals(leaf_hash_3, "0x56c3dcca6e8900359d7172be38a74da7a350a7af2ab102fbb3fd251d57f76316");
   }
})

Clarinet.test({
    name: "Ensure that block can be committed by subnet miner",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // valid miner
        const alice = accounts.get("wallet_1")!;
        // invalid miner
        const bob = accounts.get("wallet_2")!;
        const charlie = accounts.get("wallet_3")!;

        // set alice as a miner
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(alice.address),
            ],
            alice.address),
        ]);

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
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 2, 2, 2, 2]));
    },
});

Clarinet.test({
    name: "Ensure that user can register and setup assets ",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // valid miner
        const alice = accounts.get("wallet_1")!;
        // invalid miner
        const bob = accounts.get("wallet_2")!;

        // contract ids
        const second_nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.second-simple-nft")!;
        const second_ft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.second-simple-ft")!;


        // set alice as a miner
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(alice.address),
            ],
            alice.address),
        ]);

        // Invalid miner can't setup allowed assets
        let block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                bob.address),
        ]);
        // should return (err ERR_INVALID_MINER)
        block.receipts[0].result
            .expectErr()
            .expectInt(2);

        // Miner can set up allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Miner should not be able to set up allowed assets a second time
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                alice.address),
        ]);
        // should return (err ERR_ASSET_ALREADY_ALLOWED)
        block.receipts[0].result
            .expectErr()
            .expectInt(6);

        // Miner should be able to register a new allowed NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "register-new-nft-contract",
                [
                    types.principal(second_nft_contract.contract_id),
                    types.ascii("deposit-on-hc"),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Miner should be not able to register a previously allowed NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "register-new-nft-contract",
                [
                    types.principal(second_nft_contract.contract_id),
                    types.ascii("deposit-on-hc"),
                ],
                alice.address),
        ]);
        // should return (err ERR_ASSET_ALREADY_ALLOWED)
        block.receipts[0].result
            .expectErr()
            .expectInt(6);

        // Miner should be able to register a new allowed FT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "register-new-ft-contract",
                [
                    types.principal(second_ft_contract.contract_id),
                    types.ascii("deposit-on-hc"),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Miner should be not able to register a previously allowed FT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "register-new-ft-contract",
                [
                    types.principal(second_ft_contract.contract_id),
                    types.ascii("deposit-on-hc"),
                ],
                alice.address),
        ]);
        // should return (err ERR_ASSET_ALREADY_ALLOWED)
        block.receipts[0].result
            .expectErr()
            .expectInt(6);

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

        // set alice as a miner
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(alice.address),
            ],
            alice.address),
        ]);
        
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

        let root_hash = fromHex("fd5ece9024d526e1114ef41ce319a129053d739e0f81960483209d49aec29e62");
        let nft_sib_hash = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
        let nft_leaf_hash = fromHex("1964591d7db5eaad6d89e8556303ed932d1dffd0420b6d76476f8e8b84f11401");

        // Miner should commit a block with the appropriate root hash (mocking a withdrawal Merkle tree)
        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();

        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // Miner should be able to withdraw NFT asset for user
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.some(types.principal(nft_contract.contract_id)),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])

                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check that user owns NFT
        assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        nft_amount = assets[charlie.address];
        assertEquals(nft_amount, 1);


        // Miner should not be able to withdraw NFT asset a second time
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.some(types.principal(nft_contract.contract_id)),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])

                ],
                alice.address),
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

        // set alice as a miner
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(alice.address),
            ],
            alice.address),
        ]);

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

        let ft_leaf_hash = fromHex("0710ad82cb4fd77b664629f8079b9410b1fcbd6b2b057edd39f6397eb8f37c03"); //new Uint8Array([33, 202, 115, 15, 237, 187, 156, 88, 59, 212, 42, 195, 30, 149, 130, 0, 37, 203, 93, 165, 189, 33, 107, 213, 116, 211, 170, 0, 89, 231, 154, 3]);
        let root_hash = fromHex("c075d6e19bbe76e23cff6256d97333941e1365feb7d16572f8eba8cbc39f6c64"); // new Uint8Array([203, 225, 170, 121, 99, 143, 221, 118, 153, 59, 252, 68, 117, 30, 27, 33, 49, 100, 166, 167, 250, 154, 172, 149, 149, 79, 236, 105, 254, 184, 172, 103]);
        let ft_sib_hash = new Uint8Array([38, 72, 158, 13, 57, 120, 9, 95, 13, 62, 11, 118, 71, 237, 60, 173, 121, 221, 127, 38, 163, 75, 203, 191, 227, 4, 195, 17, 239, 76, 42, 55]);
                
        // Miner should commit a block with the appropriate root hash
        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // Miner should be able to withdraw FT asset for user
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.principal(ft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(ft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(ft_sib_hash),
                        "is-left-side": types.bool(false)
                    })])

                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check that user owns FT
        let assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        let ft_amount = assets[charlie.address];
        assertEquals(ft_amount, 1);

        // Miner should not be able to withdraw FT asset a second time
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.principal(ft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(ft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(ft_sib_hash),
                        "is-left-side": types.bool(false)
                    })])

                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

    },
});

Clarinet.test({
    name: "Ensure that user can withdraw FT minted on hyperchain & L1 miner can mint it",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // miner
        const alice = accounts.get("wallet_1")!;
        // user
        const charlie = accounts.get("wallet_3")!;

        // ft contract
        const ft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-ft")!;

        // set alice as a miner
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(alice.address),
            ],
            alice.address),
        ]);

        // User should be able to mint a fungible token
        let block = chain.mineBlock([
            Tx.contractCall("simple-ft", "gift-tokens", [types.principal(charlie.address)], charlie.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);

        // Check that user owns FT
        let assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        let ft_amount = assets[charlie.address];
        assertEquals(ft_amount, 1);

        // Miner sets up allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should be able to deposit FT asset
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
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check that user no longer owns FT
        assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        ft_amount = assets[charlie.address];
        assertEquals(ft_amount, 0);

        // Miner should commit a block with the appropriate root hash
        // Mocks a withdrawal of ft-token for amount 3
        let ft_leaf_hash = fromHex("b393fb2ea05f2f28535cee6111de603996bbf4de5b15321f3e6b4258e933c7aa");
        let root_hash = fromHex("2390d2b6476c5cb4543a67b7f1d5cc1ba979f5b9963f4b7c640d3828dd21f94f");
        let ft_sib_hash = fromHex("0000000000000000000000000000000000000000000000000000000000000000");

        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // Miner should be able to withdraw FT asset for user
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(3),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.principal(ft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(ft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(ft_sib_hash),
                        "is-left-side": types.bool(false)
                    })])

                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check that user owns FT
        assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        ft_amount = assets[charlie.address];
        assertEquals(ft_amount, 3);

        // Miner should be not be able to withdraw FT asset with same hash
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(3),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                    types.principal(ft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(ft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(ft_sib_hash),
                        "is-left-side": types.bool(false)
                    })])

                ],
                alice.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

        // User should be not be able to withdraw 0 amount of FT asset
        // This test works since the amount is checked before the leaf hash is checked
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(0),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.none(),
                    types.principal(ft_contract.contract_id),
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
        // should return (err ERR_ATTEMPT_TO_TRANSFER_ZERO_AMOUNT)
        block.receipts[0].result
            .expectErr()
            .expectInt(14);

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

        const recipient = "ST18F1AHKW194BWQ3CEFDPWVRARA79RBGFEWSDQR8";

        // get address of contracts
        const ft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-ft")!;
        const nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-nft")!;

        // set alice as a miner
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(alice.address),
            ],
            alice.address),
        ]);

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

        let root_hash = fromHex("b02609e344ebb6525c83cd6c2bd3d2a1c73daa2c9344119f036d615b110aad15");

        let ft_leaf_hash = fromHex("be7bcffde781f217150cfc63c88fc2e78bca424b318f5421abdfe96842321e79");
        let stx_leaf_hash = fromHex("bde3658bbc38952599ef925ea3075a2fbfc5619cebf48cce140994c8b328fe35");
        let nft_leaf_hash = fromHex("6456c2cdb1c1016fddf2e9b7eb88cd677741f0420614a824ac8b774a24285a35");

        let ft_level_one_sib_hash = stx_leaf_hash;
        let ft_level_two_sib_hash = fromHex("8bec7ac5a0ec8eed899374f25fa8c0aa67e852b0c5a99ff6595e589a8d123ea0");

        let stx_level_one_sib_hash = ft_leaf_hash;
        let stx_level_two_sib_hash = ft_level_two_sib_hash;

        let nft_level_one_sib_hash = nft_leaf_hash;
        let nft_level_two_sib_hash = fromHex("a00db116739a78d6547e18399924b8ec0201079149369b43422e816587f97ede");

        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();

        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // Miner should be able to withdraw FT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(recipient),
                    types.uint(1),
                    types.uint(0),
                    types.none(),
                    types.principal(ft_contract.contract_id),
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
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Miner should be able to withdraw STX

        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-stx",
                [
                    types.uint(1),
                    types.principal(recipient),
                    types.uint(0),
                    types.uint(0),
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
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Miner should be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(recipient),
                    types.uint(2),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.some(types.principal(nft_contract.contract_id)),
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
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check balances after withdrawals
        stx_assets = chain.getAssetsMaps().assets["STX"];
        stx_amount = stx_assets[charlie.address];
        assertEquals(stx_amount, charlie_init_balance-5);
        stx_amount = stx_assets[recipient];
        assertEquals(stx_amount, 1);
        ft_assets = chain.getAssetsMaps().assets[".simple-ft.ft-token"];
        ft_amount = ft_assets[recipient];
        assertEquals(ft_amount, 1);
        nft_assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        nft_amount = nft_assets[recipient];
        assertEquals(nft_amount, 1);

        // For safety, check that miner can't withdraw FT asset a second time with same key
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(recipient),
                    types.uint(1),
                    types.uint(0),
                    types.none(),
                    types.principal(ft_contract.contract_id),
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
                alice.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

        // For safety, check that miner can't withdraw STX asset a second time with same key
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-stx",
                [
                    types.uint(1),
                    types.principal(recipient),
                    types.uint(0),
                    types.uint(0),
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
                alice.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

        // For safety, check that miner can't withdraw NFT asset a second time with same key
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(recipient),
                    types.uint(2),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.some(types.principal(nft_contract.contract_id)),
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
                alice.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);

    },
});

Clarinet.test({
    name: "Ensure that L1 contract can't mint an NFT first created on the hyperchain if it already exists on the L1",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // miner
        const alice = accounts.get("wallet_1")!;
        // user than owns NFT on L1
        const bob = accounts.get("wallet_2")!;
        // user that attempts to withdraw NFT minted on the hyperchain to L1
        const charlie = accounts.get("wallet_3")!;

        // nft contract id
        const nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-nft")!;

        // set alice as a miner
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(alice.address),
            ],
            alice.address),
        ]);

        // Miner sets up allowed assets
        let block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Bob should be able to mint an NFT on the L1 (id = 1)
        block = chain.mineBlock([
            Tx.contractCall("simple-nft", "test-mint", [types.principal(bob.address)], bob.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);
        // Check that Bob now owns this NFT
        let assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        let nft_amount = assets[bob.address];
        assertEquals(nft_amount, 1);

        // Miner should commit a block with the appropriate root hash (mocking a withdrawal Merkle tree)
        // This tree mocks the withdrawal of an NFT with ID = 1
        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        let root_hash = fromHex("fd5ece9024d526e1114ef41ce319a129053d739e0f81960483209d49aec29e62");
        let nft_sib_hash  = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
        let nft_leaf_hash = fromHex("1964591d7db5eaad6d89e8556303ed932d1dffd0420b6d76476f8e8b84f11401");

        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // Miner should be not able to withdraw NFT asset since it already exists on the L1
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.some(types.principal(nft_contract.contract_id)),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                            "hash": types.buff(nft_sib_hash),
                            "is-left-side": types.bool(true)
                    })])

                ],
                alice.address),
        ]);
        // should return (err ERR_MINT_FAILED)
        block.receipts[0].result
            .expectErr()
            .expectInt(13);

    },

});

Clarinet.test({
    name: "Ensure that user can mint an NFT on the hyperchain and L1 miner can withdraw it by minting",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        // miner
        const alice = accounts.get("wallet_1")!;
        // user
        const charlie = accounts.get("wallet_3")!;

        // nft contract id
        const nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-nft")!;

        // set alice as a miner
        let initialize = chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(alice.address),
            ],
            alice.address),
        ]);

        // Miner sets up allowed assets
        let block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);
        // Check that user does not own this NFT on the L1
        let assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        assertEquals(assets, undefined);

        // Miner should commit a block with the appropriate root hash (mocking a withdrawal Merkle tree)
        // This tree mocks the withdrawal of an NFT with ID = 1
        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], alice.address).result.expectOk().toString();
        let root_hash = fromHex("fd5ece9024d526e1114ef41ce319a129053d739e0f81960483209d49aec29e62");
        let nft_sib_hash  = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
        let nft_leaf_hash = fromHex("1964591d7db5eaad6d89e8556303ed932d1dffd0420b6d76476f8e8b84f11401");

        block = chain.mineBlock([
            // Successfully commit block at height 0 with alice.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // Miner should be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),                    
                    types.principal(nft_contract.contract_id),
                    types.some(types.principal(nft_contract.contract_id)),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);
        // Check that user owns NFT on the L1
        assets = chain.getAssetsMaps().assets[".simple-nft.nft-token"];
        let nft_amount = assets[charlie.address];
        assertEquals(nft_amount, 1);

        // Miner should not be able to withdraw NFT asset a second time
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.uint(0),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.some(types.principal(nft_contract.contract_id)),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])
                ],
                alice.address),
        ]);
        // should return (err ERR_WITHDRAWAL_ALREADY_PROCESSED)
        block.receipts[0].result
            .expectErr()
            .expectInt(9);
    },
});

Clarinet.test({
    name: "Ensure that a miner can't withdraw an NFT if nobody owns it, in the `no-mint` case.",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        const miner = accounts.get("wallet_1")!;
        const user = accounts.get("wallet_3")!;
        const nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-nft-no-mint")!;

        chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(miner.address),
            ],
            miner.address),
        ]);


        // Miner sets up allowed assets
        let block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                miner.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check that user does not own this NFT on the L1
        let assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        assertEquals(assets, undefined);

        // Miner should commit a block with the appropriate root hash (mocking a withdrawal Merkle tree)
        // This tree mocks the withdrawal of an NFT with ID = 1
        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], miner.address).result.expectOk().toString();
        let root_hash = fromHex("381dc593ba22617f227f5e1e413f91989394fa2934fcaba7badb2d7aaf0b2d49");
        let nft_sib_hash  = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
        let nft_leaf_hash = fromHex("d95c47532db6bdf22595bbff81ca31a5128417f243988f7da23b917c67c969eb");
        block = chain.mineBlock([
            // Successfully commit block at height 0.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                miner.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // Miner should *not* be able to withdraw NFT asset because the contract doesn't own it.
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset-no-mint",
                [
                    types.uint(1),
                    types.principal(user.address),
                    types.uint(0),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])
                ],
                miner.address),
        ]);

        // ERR_NFT_NOT_OWNED_BY_CONTRACT
        block.receipts[0].result
            .expectErr()
            .expectInt(16);
    },
});

Clarinet.test({
    name: "Ensure that a miner can withdraw an NFT to the original owner, in the `no-mint` case.",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        const miner = accounts.get("wallet_1")!;
        const user = accounts.get("wallet_3")!;
        const nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-nft-no-mint")!;

        chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(miner.address),
            ],
            miner.address),
        ]);

        // User should be able to mint an NFT
        let block = chain.mineBlock([
            Tx.contractCall("simple-nft-no-mint", "test-mint", [types.principal(user.address)], user.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);
        // Check that user owns NFT
        let assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        let nft_amount = assets[user.address];
        assertEquals(nft_amount, 1);

        // Miner sets up allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                miner.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should be able to deposit NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-nft-asset",
                [
                    types.uint(1),
                    types.principal(user.address),
                    types.principal(nft_contract.contract_id),
                    types.principal(nft_contract.contract_id),
                ],
                user.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);
        
        // Check that user *does not* own the NFT
        assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        nft_amount = assets[user.address];
        assertEquals(nft_amount, 0);

        // Miner commits block.
        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], miner.address).result.expectOk().toString();
        let root_hash = fromHex("381dc593ba22617f227f5e1e413f91989394fa2934fcaba7badb2d7aaf0b2d49");
        let nft_sib_hash  = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
        let nft_leaf_hash = fromHex("d95c47532db6bdf22595bbff81ca31a5128417f243988f7da23b917c67c969eb");

        block = chain.mineBlock([
            // Successfully commit block at height 0.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                miner.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));


        // Miner should be able to withdraw NFT asset to original user.
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset-no-mint",
                [
                    types.uint(1),
                    types.principal(user.address),
                    types.uint(0),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])
                ],
                miner.address),
        ]);

        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Check that original user owns NFT.
        assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        nft_amount = assets[user.address];
        assertEquals(nft_amount, 1);
    },
});

Clarinet.test({
    name: "Ensure that a miner can withdraw an NFT to a different user, in the `no-mint` case.",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        // `original_user` deposits the NFT, but the miner withdraws it to `other_user`.
        const miner = accounts.get("wallet_1")!;
        const original_user = accounts.get("wallet_2")!;
        const other_user = accounts.get("wallet_3")!;

        const nft_contract = contracts.get("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.simple-nft-no-mint")!;

        chain.mineBlock([
            Tx.contractCall("hyperchains", "set-hc-miner",
            [
                types.principal(miner.address),
            ],
            miner.address),
        ]);

        // Original user should be able to mint an NFT.
        let block = chain.mineBlock([
            Tx.contractCall("simple-nft-no-mint", "test-mint", [types.principal(original_user.address)], original_user.address),
        ]);
        block.receipts[0].result.expectOk().expectBool(true);

        // Check that original user owns NFT.
        let assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        let nft_amount = assets[original_user.address];
        assertEquals(nft_amount, 1);

        // Check that other user does *not* own the NFT.
        assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        nft_amount = assets[other_user.address];
        assertEquals(nft_amount, undefined);

        // Miner sets up allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                miner.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // User should be able to deposit NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-nft-asset",
                [
                    types.uint(1),
                    types.principal(original_user.address),
                    types.principal(nft_contract.contract_id),
                    types.principal(nft_contract.contract_id),
                ],
                original_user.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Neither user should own the NFT.
        assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        nft_amount = assets[original_user.address];
        assertEquals(nft_amount, 0);
        assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        nft_amount = assets[other_user.address];
        assertEquals(nft_amount, undefined);

        // Miner commits a block.
        let root_hash = fromHex("381dc593ba22617f227f5e1e413f91989394fa2934fcaba7badb2d7aaf0b2d49");
        let nft_sib_hash  = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
        let nft_leaf_hash = fromHex("d95c47532db6bdf22595bbff81ca31a5128417f243988f7da23b917c67c969eb");

        const id_header_hash = chain.callReadOnlyFn('test-helpers', 'get-id-header-hash', [], miner.address).result.expectOk().toString();
        block = chain.mineBlock([
            // Successfully commit block at height 0.
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                    id_header_hash,
                    types.buff(root_hash),
                ],
                miner.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));

        // Miner should be able to withdraw NFT asset to other_user.
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset-no-mint",
                [
                    types.uint(1),
                    types.principal(other_user.address),
                    types.uint(0),
                    types.uint(0),
                    types.principal(nft_contract.contract_id),
                    types.buff(root_hash),
                    types.buff(nft_leaf_hash),
                    types.list([types.tuple({
                        "hash": types.buff(nft_sib_hash),
                        "is-left-side": types.bool(true)
                    })])
                ],
                miner.address),
        ]);

        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // `other_user` owns the NFT now. `original_user` doesn't.
        assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        nft_amount = assets[original_user.address];
        assertEquals(nft_amount, 0);
        assets = chain.getAssetsMaps().assets[".simple-nft-no-mint.nft-token"];
        nft_amount = assets[other_user.address];
        assertEquals(nft_amount, 1);
    },
});
