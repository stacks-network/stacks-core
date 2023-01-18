
import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v1.3.1/index.ts';
import { assertEquals } from 'https://deno.land/std@0.170.0/testing/asserts.ts';

Clarinet.test({
    name: "Ensure that coordinator starts empty",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        let deployer = accounts.get("deployer")!;

        let coordinator = chain.callReadOnlyFn("sbtc-token-key-admin", "get-coordinator-key", [], deployer.address);

        coordinator.result.expectNone();

        //assertEquals(block.height, 3);
    },
});

Clarinet.test({
    name: "Ensure that coordinator can be written then read",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        let deployer = accounts.get("deployer")!;

        let block = chain.mineBlock([
            // Generate a contract call to count-up from the deployer address.
            Tx.contractCall("sbtc-token-key-admin", "set-coordinator-key", [types.principal(deployer.address)], deployer.address),
        ]);

        // Get the first (and only) transaction receipt.
        let [receipt] = block.receipts;

        // Assert that the returned result is a boolean true.
        receipt.result.expectOk().expectBool(true);

        let coordinator = chain.callReadOnlyFn("sbtc-token-key-admin", "get-coordinator-key", [], deployer.address);

        coordinator.result.expectSome(deployer.address);
    },
});

Clarinet.test({
    name: "Ensure that signer can be written then read",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        let deployer = accounts.get("deployer")!;

        let block = chain.mineBlock([
            // Generate a contract call to count-up from the deployer address.
            Tx.contractCall("sbtc-token-key-admin", "set-signer-key", [types.uint(1), types.principal(deployer.address)], deployer.address),
        ]);

        // Get the first (and only) transaction receipt.
        let [receipt] = block.receipts;

        // Assert that the returned result is a boolean true.
        receipt.result.expectOk().expectBool(true);

        let coordinator = chain.callReadOnlyFn("sbtc-token-key-admin", "get-signer-key", [types.uint(1)], deployer.address);

        coordinator.result.expectSome(deployer.address);
    },
});
