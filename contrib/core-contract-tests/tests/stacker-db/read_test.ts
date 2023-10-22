import { Clarinet, Tx, Chain, Account, Contract, types } from 'https://deno.land/x/clarinet@v1.1.0/index.ts';
import { assertEquals } from "https://deno.land/std@0.90.0/testing/asserts.ts";
import { createHash } from "https://deno.land/std@0.107.0/hash/mod.ts";

Clarinet.test({
    name: "Ensure that the current-pox-reward-cycle function returns the correct value (0)",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        const deployer = accounts.get("deployer")!;
        const alice = accounts.get("wallet_1")!;
        const bob = accounts.get("wallet_2")!;
        const charlie = accounts.get("wallet_3")!;
        const dave = accounts.get("wallet_4")!;

        let call = chain.callReadOnlyFn("stacker-db", "current-pox-reward-cycle", [], deployer.address)
        assertEquals(call.result, types.uint(0));
    },
});
