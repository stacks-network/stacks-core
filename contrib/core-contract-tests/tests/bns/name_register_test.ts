/* This Clarinet v1 tests have been migrated to the clarinet-sdk */
/* This file is still executed in the CI in order to avoid false positives or negatives in the CI */
/* https://github.com/stacks-network/stacks-blockchain/pull/4031#pullrequestreview-1713341208 */

import { Clarinet, Tx, Chain, Account, Contract, types } from 'https://deno.land/x/clarinet@v1.1.0/index.ts';
import { assertEquals } from "https://deno.land/std@0.90.0/testing/asserts.ts";
import { createHash } from "https://deno.land/std@0.107.0/hash/mod.ts";

Clarinet.test({
    name: "Ensure that name can be registered",
    async fn(chain: Chain, accounts: Map<string, Account>, contracts: Map<string, Contract>) {

        const alice = accounts.get("wallet_1")!;
        const bob = accounts.get("wallet_2")!;
        const charlie = accounts.get("wallet_3")!;
        const dave = accounts.get("wallet_4")!;

        const cases = [{
            namespace: "blockstack",
            version: 1,
            salt: "0000",
            value: 640000000,
            namespaceOwner: alice,
            nameOwner: bob,
            priceFunction: [
                types.uint(4),   // base
                types.uint(250), // coeff
                types.uint(7),   // bucket 1
                types.uint(6),   // bucket 2
                types.uint(5),   // bucket 3
                types.uint(4),   // bucket 4
                types.uint(3),   // bucket 5
                types.uint(2),   // bucket 6
                types.uint(1),   // bucket 7
                types.uint(1),   // bucket 8
                types.uint(1),   // bucket 9
                types.uint(1),   // bucket 10
                types.uint(1),   // bucket 11
                types.uint(1),   // bucket 12
                types.uint(1),   // bucket 13
                types.uint(1),   // bucket 14
                types.uint(1),   // bucket 15
                types.uint(1),   // bucket 16+
                types.uint(4),   // nonAlphaDiscount
                types.uint(4),   // noVowelDiscount
            ],
            renewalRule: 10,
            nameImporter: alice,
            zonefile: "0000",
        }, {
            namespace: "id",
            version: 1,
            salt: "0000",
            value: 64000000000,
            namespaceOwner: alice,
            nameOwner: bob,
            priceFunction: [
                types.uint(4),   // base
                types.uint(250), // coeff
                types.uint(6),   // bucket 1
                types.uint(5),   // bucket 2
                types.uint(4),   // bucket 3
                types.uint(3),   // bucket 4
                types.uint(2),   // bucket 5
                types.uint(1),   // bucket 6
                types.uint(0),   // bucket 7
                types.uint(0),   // bucket 8
                types.uint(0),   // bucket 9
                types.uint(0),   // bucket 10
                types.uint(0),   // bucket 11
                types.uint(0),   // bucket 12
                types.uint(0),   // bucket 13
                types.uint(0),   // bucket 14
                types.uint(0),   // bucket 15
                types.uint(0),   // bucket 16+
                types.uint(20),  // nonAlphaDiscount
                types.uint(20),  // noVowelDiscount
            ],
            renewalRule: 20,
            nameImporter: alice,
            zonefile: "1111",
        }];
        
        let call = chain.callReadOnlyFn("bns", "resolve-principal", [types.principal(bob.address)], alice.address)
        let error:any = call.result
            .expectErr()
            .expectTuple();
        error['code'].expectInt(2013);

        // Registering a name at this point should fail, namespace have not been registered yet
        let block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[1].namespace), 
                    types.buff("bob"), 
                    types.buff(cases[1].salt), 
                    types.buff(cases[1].zonefile)
                ], 
                cases[0].nameOwner.address),
        ]);
        assertEquals(block.height, 2);
        block.receipts[0].result
            .expectErr()
            .expectInt(1005);

        // Preorder a namespace
        let merged = new TextEncoder().encode(`${cases[1].namespace}${cases[1].salt}`);
        let sha256 = createHash("sha256")
            .update(merged)
            .digest();
        let ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "namespace-preorder", 
                [
                    types.buff(ripemd160), 
                    types.uint(cases[1].value)
                ], 
                cases[1].namespaceOwner.address),
        ]);
        assertEquals(block.height, 3);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        // Reveal the namespace
        block = chain.mineBlock([
            Tx.contractCall("bns", "namespace-reveal", 
                [
                    types.buff(cases[1].namespace),
                    types.buff(cases[1].salt),
                    ...cases[1].priceFunction,
                    types.uint(cases[1].renewalRule),
                    types.principal(cases[1].nameImporter.address),
                ], 
                cases[1].namespaceOwner.address),
        ]);
        assertEquals(block.height, 4);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Bob can now preorder a name
        let name = "baobab";
        merged = new TextEncoder().encode(`${name}.${cases[1].namespace}${cases[1].salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-preorder", 
                [
                    types.buff(ripemd160),
                    types.uint(100),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 5);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        // But revealing the name should fail - the namespace was not launched yet
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[1].namespace),
                    types.buff(name),
                    types.buff(cases[1].salt),
                    types.buff(cases[1].zonefile),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 6);
        block.receipts[0].result
            .expectErr()
            .expectInt(2004);

        // // Given a launched namespace 'blockstack', owned by Alice
        merged = new TextEncoder().encode(`${cases[0].namespace}${cases[0].salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "namespace-preorder", 
                [
                    types.buff(ripemd160), 
                    types.uint(cases[0].value)
                ], 
                cases[0].namespaceOwner.address),
        ]);
        assertEquals(block.height, 7);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        // Reveal the namespace
        block = chain.mineBlock([
            Tx.contractCall("bns", "namespace-reveal", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(cases[0].salt),
                    ...cases[0].priceFunction,
                    types.uint(cases[0].renewalRule),
                    types.principal(cases[0].nameImporter.address),
                ], 
                cases[0].namespaceOwner.address),
        ]);
        assertEquals(block.height, 8);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Launch the namespace
        block = chain.mineBlock([
            Tx.contractCall("bns", "namespace-ready", 
                [
                    types.buff(cases[0].namespace),
                ], 
                cases[0].namespaceOwner.address),
        ]);
        assertEquals(block.height, 9);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        // Revealing the name 'bob.blockstack'
        // should fail if no matching pre-order can be found
        // But revealing the name should fail - the namespace was not launched yet
        name = "bob";
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(name),
                    types.buff(cases[0].salt),
                    types.buff(cases[0].zonefile),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 10);
        block.receipts[0].result
            .expectErr()
            .expectInt(2001);
        
        // Bob can now preorder a name
        name = "bub";
        merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${cases[0].salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-preorder", 
                [
                    types.buff(ripemd160),
                    types.uint(2559999),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 11);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        // should fail
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff("bub"),
                    types.buff(cases[0].salt),
                    types.buff(cases[0].zonefile),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 12);
        block.receipts[0].result
            .expectErr()
            .expectInt(2007);
    
        // Given an existing pre-order of the name 'Bob.blockstack'
        name = "Bob";
        merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${cases[0].salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-preorder", 
                [
                    types.buff(ripemd160),
                    types.uint(2560000),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 13);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);
    
        // Bob registering the name 'Bob.blockstack' should fail
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(name),
                    types.buff(cases[0].salt),
                    types.buff(cases[0].zonefile),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 14);
        block.receipts[0].result
            .expectErr()
            .expectInt(2022);
    
        // Given an existing pre-order of the name 'bob.blockstack'
        name = "bob";
        merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${cases[0].salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-preorder", 
                [
                    types.buff(ripemd160),
                    types.uint(2560000),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 15);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        // Bob registering the name 'bob.blockstack' should succeed
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(name),
                    types.buff(cases[0].salt),
                    types.buff(cases[0].zonefile),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 16);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        call = chain.callReadOnlyFn("bns", "resolve-principal", [types.principal(bob.address)], alice.address)
        let response:any = call.result
            .expectOk()
            .expectTuple();
        response["name"].expectBuff("bob");
        response["namespace"].expectBuff("blockstack");

        call = chain.callReadOnlyFn("bns", "name-resolve", [types.buff(cases[0].namespace), types.buff(name)], alice.address)
        response = call.result
            .expectOk()
            .expectTuple();
        response["owner"].expectPrincipal(bob.address);
        response["zonefile-hash"].expectBuff(cases[0].zonefile);

        // should fail registering twice
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(name),
                    types.buff(cases[0].salt),
                    types.buff(cases[0].zonefile),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 17);
        block.receipts[0].result
            .expectErr()
            .expectInt(2004);
    
        // Charlie registering 'bob.blockstack'
        // should fail
        name = "bob";
        let salt = "1111"
        merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-preorder", 
                [
                    types.buff(ripemd160),
                    types.uint(2560000),
                ], 
                charlie.address),
        ]);
        assertEquals(block.height, 18);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        // Bob registering the name 'bob.blockstack' should succeed
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(name),
                    types.buff(salt),
                    types.buff(cases[0].zonefile),
                ], 
                charlie.address),
        ]);
        assertEquals(block.height, 19);
        block.receipts[0].result
            .expectErr()
            .expectInt(2004);
    
        // Bob registering a second name 'bobby.blockstack'
        // should fail if 'bob.blockstack' is not expired
        name = "bobby";
        salt = "1111"
        merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-preorder", 
                [
                    types.buff(ripemd160),
                    types.uint(2560000),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 20);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        // Bob registering the name 'bob.blockstack' should succeed
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(name),
                    types.buff(salt),
                    types.buff(cases[0].zonefile),
                ], 
                bob.address),
        ]);
        assertEquals(block.height, 21);
        block.receipts[0].result
            .expectErr()
            .expectInt(3001);
    
        // should succeed once 'bob.blockstack' is expired
        chain.mineEmptyBlock(cases[0].renewalRule + 5000);
    
        call = chain.callReadOnlyFn("bns", "resolve-principal", [types.principal(bob.address)], alice.address)
        response = call.result
            .expectErr()
            .expectTuple();
        response["code"].expectInt("2008"); // Indicates ERR_NAME_EXPIRED
        let inner:any = response["name"].expectSome().expectTuple();
        inner["name"].expectBuff("bob");
        inner["namespace"].expectBuff("blockstack");


        name = "bobby";
        salt = "1111"
        merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-preorder", 
                [
                    types.buff(ripemd160),
                    types.uint(2560000),
                ], 
                bob.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        // Bob registering the name 'bobby.blockstack' should succeed
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(name),
                    types.buff(salt),
                    types.buff(cases[0].zonefile),
                ], 
                bob.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);
        
        // Charlie registering 'bob.blockstack'
        // should succeed once 'bob.blockstack' is expired
        name = "bob";
        salt = "2222"
        merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${salt}`);
        sha256 = createHash("sha256")
            .update(merged)
            .digest();
        ripemd160 = createHash("ripemd160")
            .update(sha256)
            .digest();
        block = chain.mineBlock([
            Tx.contractCall("bns", "name-preorder", 
                [
                    types.buff(ripemd160),
                    types.uint(2560000),
                ], 
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectUint(144 + block.height - 1);

        block = chain.mineBlock([
            Tx.contractCall("bns", "name-register", 
                [
                    types.buff(cases[0].namespace),
                    types.buff(name),
                    types.buff(salt),
                    types.buff("CHARLIE"),
                ], 
                charlie.address),
        ]);
        block.receipts[0].result
            .expectOk()
            .expectBool(true);

        call = chain.callReadOnlyFn("bns", "name-resolve", [types.buff(cases[0].namespace), types.buff(name)], alice.address)
        response = call.result
            .expectOk()
            .expectTuple();
        response["owner"].expectPrincipal(charlie.address);
        response["zonefile-hash"].expectBuff("CHARLIE");        
    },
});
