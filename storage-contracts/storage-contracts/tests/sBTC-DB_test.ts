
import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v1.7.1/index.ts';
import { assertEquals } from 'https://deno.land/std@0.170.0/testing/asserts.ts';

Clarinet.test({
    name: "Ensure that <...>",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        // arrange: set up the chain, state, and other required elements
        let wallet_1 = accounts.get("wallet_1")!;

        // act: perform actions related to the current test
        let block = chain.mineBlock([
            /*
             * Add transactions with:
             * Tx.contractCall(...)
            */
        ]);

        // assert: review returned data, contract state, and other requirements
        assertEquals(block.receipts.length, 0);
        assertEquals(block.height, 2);

        // TODO
        assertEquals("TODO", "a complete test");
    },
});
