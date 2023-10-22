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

Clarinet.test({
    name: "Ensure that the current-pox-reward-cycle function returns the correct value after mining a cycle of empty blocks (1)",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        const deployer = accounts.get("deployer")!;
        const alice = accounts.get("wallet_1")!;
        const bob = accounts.get("wallet_2")!;
        const charlie = accounts.get("wallet_3")!;
        const dave = accounts.get("wallet_4")!;

        chain.mineEmptyBlockUntil(2101);

        let call = chain.callReadOnlyFn("stacker-db", "current-pox-reward-cycle", [], deployer.address)
        assertEquals(call.result, types.uint(1));
    },
});

Clarinet.test({
    name: "Ensure that stackerdb can only be updated during 'prepare phase'",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        const deployer = accounts.get("deployer")!;
        const alice = accounts.get("wallet_1")!;
        const bob = accounts.get("wallet_2")!;
        const charlie = accounts.get("wallet_3")!;
        const dave = accounts.get("wallet_4")!;

        chain.mineEmptyBlockUntil(2101);

        let block = chain.mineBlock([
            Tx.contractCall("stacker-db", "stackerdb-set-next-cycle-signer-slots", 
                [
                    types.list([
                        types.tuple({
                            signer: types.principal(alice.address),
                            numslots: types.uint(1),
                        })
                    ]),
                ], 
                deployer.address),
        ]);

        block.receipts[0].result
            .expectErr()
            .expectUint(2001);
    },
});

Clarinet.test({
    name: "Ensure that stackerdb cannot be updated by deployer / any non-pox4 contract",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        const deployer = accounts.get("deployer")!;
        const alice = accounts.get("wallet_1")!;
        const bob = accounts.get("wallet_2")!;
        const charlie = accounts.get("wallet_3")!;
        const dave = accounts.get("wallet_4")!;

        chain.mineEmptyBlockUntil(4150);

        let block = chain.mineBlock([
            Tx.contractCall("stacker-db", "stackerdb-set-next-cycle-signer-slots", 
                [
                    types.list([
                        types.tuple({
                            signer: types.principal(alice.address),
                            numslots: types.uint(1),
                        })
                    ]),
                ], 
                deployer.address),
        ]);

        block.receipts[0].result
            .expectErr()
            .expectUint(2000);
    },
});

Clarinet.test({
    name: "Ensure that submitted signer slots are not empty",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {
        const deployer = accounts.get("deployer")!;
        const alice = accounts.get("wallet_1")!;
        const bob = accounts.get("wallet_2")!;
        const charlie = accounts.get("wallet_3")!;
        const dave = accounts.get("wallet_4")!;

        chain.mineEmptyBlockUntil(4150);

        let block = chain.mineBlock([
            Tx.contractCall("stacker-db", "stackerdb-set-next-cycle-signer-slots", 
                [
                    types.list([
                    ]),
                ], 
                deployer.address),
        ]);

        block.receipts[0].result
            .expectErr()
            .expectUint(2003);
    },
});