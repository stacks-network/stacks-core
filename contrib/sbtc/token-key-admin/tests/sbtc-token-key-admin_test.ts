
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

Clarinet.test({
    name: "Ensure that signer can be written then deleted",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        let deployer = accounts.get("deployer")!;

        let block_set = chain.mineBlock([
            // Generate a contract call to count-up from the deployer address.
            Tx.contractCall("sbtc-token-key-admin", "set-signer-key", [types.uint(1), types.principal(deployer.address)], deployer.address),
        ]);

        // Get the first (and only) transaction receipt.
        let [receipt_set] = block_set.receipts;

        // Assert that the returned result is a boolean true.
        receipt_set.result.expectOk().expectBool(true);

        let coordinator_set = chain.callReadOnlyFn("sbtc-token-key-admin", "get-signer-key", [types.uint(1)], deployer.address);

        coordinator_set.result.expectSome(deployer.address);

        let block_delete = chain.mineBlock([
            // Generate a contract call to count-up from the deployer address.
            Tx.contractCall("sbtc-token-key-admin", "delete-signer-key", [types.uint(1)], deployer.address),
        ]);

        // Get the first (and only) transaction receipt.
        let [receipt_delete] = block_delete.receipts;

        // Assert that the returned result is a boolean true.
        receipt_delete.result.expectOk().expectBool(true);

        let coordinator_delete = chain.callReadOnlyFn("sbtc-token-key-admin", "get-signer-key", [types.uint(1)], deployer.address);

        coordinator_delete.result.expectNone();
    },
});

Clarinet.test({
    name: "Ensure we can mint tokens",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        let deployer = accounts.get("deployer")!;

        let balance = chain.callReadOnlyFn("sbtc-token-key-admin", "get-balance", [types.principal(deployer.address)], deployer.address);

        balance.result.expectOk().expectUint(0);

        let block = chain.mineBlock([
            // Generate a contract call to count-up from the deployer address.
            Tx.contractCall("sbtc-token-key-admin", "mint!", [types.uint(1234)], deployer.address),
        ]);

        // Get the first (and only) transaction receipt.
        let [receipt] = block.receipts;

        // Assert that the returned result is a boolean true.
        //receipt.result.expectOk().expectBool(true);

        balance = chain.callReadOnlyFn("sbtc-token-key-admin", "get-balance", [types.principal(deployer.address)], deployer.address);

        balance.result.expectOk().expectUint(1234);
    },
});
