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

        let block = chain.mineBlock([
          // Successfully commit block at height 0 with alice.
          Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 1, 1, 1, 1])),
                ],
                alice.address),
          // Try and fail to commit a different block, but again at height 0.
          Tx.contractCall("hyperchains", "commit-block",
        ]);
        assertEquals(block.height, 2);
        block.receipts[0].result
            .expectOk()
            .expectBuff(new Uint8Array([0, 1, 1, 1, 1]));
        block.receipts[1].result
            .expectErr()
            .expectInt(3);


        // Try and fail to commit a block at height 1 with an invalid miner.
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
                ],
                bob.address),
        ]);
        assertEquals(block.height, 3);
        block.receipts[0].result
            .expectErr()
            .expectInt(3);

        // Successfully commit block at height 1 with valid miner.
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "commit-block",
                [
                    types.buff(new Uint8Array([0, 2, 2, 2, 2])),
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
        let assets = chain.getAssetsMaps().assets[".simple-nft.nft"];
        let nft_amount = assets[charlie.address];
        assertEquals(nft_amount, 1);

        // User should not be able to deposit NFT asset before miner allows the asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-nft-asset",
                [
                    types.uint(1),
                    types.principal(charlie.address),
                    types.principal(nft_contract.contract_id),
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(6);

        // Invalid miner can't setup allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                bob.address),
        ]);
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
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);
        // Check that contract owns NFT, and that the user does not
        assets = chain.getAssetsMaps().assets[".simple-nft.nft"];
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
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(5);

        // User should not be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
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

        // Invalid miner should not be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
                [
                    types.uint(1),
                    types.principal(bob.address),
                    types.principal(nft_contract.contract_id),
                ],
                bob.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(2);

        // Miner should be able to withdraw NFT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
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
            Tx.contractCall("hyperchains", "withdraw-nft-asset",
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

        // // User should not be able to deposit FT assets if they are not allowed
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-ft-asset",
                [
                    types.uint(2),
                    types.principal(charlie.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(6);

        // Invalid miner can't setup allowed assets
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "setup-allowed-contracts",
                [],
                bob.address),
        ]);
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
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(5);

        // User should be able to deposit FT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "deposit-ft-asset",
                [
                    types.uint(2),
                    types.principal(charlie.address),
                    types.none(),
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
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(5);

        // User should not be able to withdraw FT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(bob.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                ],
                charlie.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(2);

        // Invalid miner should not be able to withdraw FT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(bob.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                ],
                bob.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(2);

        // Miner should be able to withdraw FT asset
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(2),
                    types.principal(bob.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);


        // Miner should not be able to withdraw FT asset a second time
        block = chain.mineBlock([
            Tx.contractCall("hyperchains", "withdraw-ft-asset",
                [
                    types.uint(1),
                    types.principal(bob.address),
                    types.none(),
                    types.principal(ft_contract.contract_id),
                ],
                alice.address),
        ]);
        block.receipts[0].result
            .expectErr()
            .expectInt(4);

    },
});
