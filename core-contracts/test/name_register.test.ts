import { Provider, ProviderRegistry, Receipt, Query } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite - NAME_REGISTER", async () => {
  let bns: BNSClient;
  let provider: Provider;

  const addresses = [
    "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
    "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
    "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR"
  ];
  const alice = addresses[0];
  const bob = addresses[1];
  const charlie = addresses[2];

  const cases = [{
    namespace: "blockstack",
    version: 1,
    salt: "0000",
    value: 96,
    namespaceOwner: alice,
    nameOwner: bob,
    priceFunction: {
      buckets: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
      base: 1,
      coeff: 2,
      noVoyelDiscount: 0,
      nonAlphaDiscount: 0,
    },
    renewalRule: 1,
    nameImporter: alice,
    zonefile: "LOREM IPSUM DOLOR SIT AMET",
  }, {
    namespace: "id",
    version: 1,
    salt: "0000",
    value: 9600,
    namespaceOwner: alice,
    nameOwner: bob,
    priceFunction: {
      buckets: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
      base: 1,
      coeff: 2,
      noVoyelDiscount: 0,
      nonAlphaDiscount: 0,
    },
    renewalRule: 1,
    nameImporter: alice,
    zonefile: "LOREM IPSUM DOLOR SIT AMET",
  }];

  before(async () => {
    provider = await ProviderRegistry.createProvider();
    bns = new BNSClient(provider);
    await bns.deployContract();
  });

  describe("Revealing the name 'bob.blockstack'", async () => {
    it("should fail if the namespace 'blockstack' is not registered");

    it("should fail if the namespace 'blockstack' is not launched");

    it("should fail if no matching pre-order can be found", async () => {
      let receipt = await bns.nameRegister(
        cases[0].namespace, 
        "bob", 
        cases[0].salt, 
        cases[0].zonefile, { sender: cases[0].nameOwner });
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('2001');    
    });
});

  describe("Given a launched namespace 'blockstack', owned by Alice", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u30');

      receipt = await bns.namespaceReveal(
        cases[0].namespace, 
        cases[0].version, 
        cases[0].salt,
        cases[0].priceFunction, 
        cases[0].renewalRule, 
        cases[0].nameImporter, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');

      receipt = await bns.namespaceReady(cases[0].namespace, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');
    });

    describe("Revealing the name 'bob.blockstack'", async () => {
      it("should fail if no matching pre-order can be found", async () => {
        let receipt = await bns.nameRegister(
          cases[0].namespace, 
          "bob", 
          cases[0].salt, 
          cases[0].zonefile, { sender: cases[0].nameOwner });
        expect(receipt.success).eq(false);
        expect(receipt.result).eq('2001');    
      });
    });
  
    describe("Given an existing pre-order of the name 'bob.blockstack', initiated by Bob at block #21", async () => {

      before(async () => {
        await provider.mineBlocks(1);

        let receipt = await bns.namePreorder(
          cases[0].namespace,
          "bob",
          cases[0].salt, 
          cases[0].value, { sender: cases[0].nameOwner });
        expect(receipt.success).eq(true);
        expect(receipt.result).eq('u31');
      });
  
      describe("Bob registering the name 'bob.blockstack'", async () => {

        it("should succeed", async () => {
          let receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bob", 
            cases[0].salt, 
            cases[0].zonefile, { sender: cases[0].nameOwner });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });
      });

      describe("Bob registering a second name 'bobby.blockstack'", async () => {

        it("should fail if 'bob.blockstack' is not expired", async () => {
          await provider.mineBlocks(1);

          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "bobby",
            cases[0].salt, 
            cases[0].value, { sender: cases[0].nameOwner });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u32');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bobby", 
            cases[0].salt, 
            cases[0].zonefile, { sender: cases[0].nameOwner });
          expect(receipt.result).eq('3001');
          expect(receipt.success).eq(false);
        });

        it("should succeed once 'bob.blockstack' is expired", async () => {
          await provider.mineBlocks(10);

          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "bobby",
            cases[0].salt, 
            cases[0].value, { sender: cases[0].nameOwner });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u42');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bobby", 
            cases[0].salt, 
            cases[0].zonefile, { sender: cases[0].nameOwner });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

      });
    });
  });
});

//   before(async () => {
//     provider = await ProviderRegistry.createProvider();
//     bns = new BNSClient(provider);
//     await bns.deployContract();
//   });

//   describe("Pre-ordering the name 'bob.blockstack'", async () => {
//     it("should fail if the hash of the FQN is mal-formed");

//     it("should fail if Bob's balance is insufficient", async () => {
//       let receipt = await bns.namePreorder(
//         cases[0].namespace,
//         "bob",
//         cases[0].salt, 
//         10000, { sender: cases[0].nameOwner });
//       expect(receipt.success).eq(false);
//       expect(receipt.result).eq('4001');    
//     });

//     it("should succeed if Bob's balance is provisioned", async () => {
//       let receipt = await bns.namePreorder(
//         cases[0].namespace,
//         "bob",
//         cases[0].salt, 
//         200, { sender: cases[0].nameOwner });
//       expect(receipt.success).eq(true);
//       expect(receipt.result).eq('u30');    
//     });

//     it("should fail if the same order is being re-submitted by Bob", async () => {
//       let receipt = await bns.namePreorder(
//         cases[0].namespace,
//         "bob",
//         cases[0].salt, 
//         200, { sender: cases[0].nameOwner });
//       expect(receipt.success).eq(false);
//       expect(receipt.result).eq('2016');    
//     });

//     it("should succeed if the same order is being re-submitted by Alice", async () => {
//       let receipt = await bns.namePreorder(
//         cases[0].namespace,
//         "bob",
//         cases[0].salt, 
//         200, { sender: alice });
//       expect(receipt.success).eq(true);
//       expect(receipt.result).eq('u30');    
//     });

//     it("should succeed once claimability TTL expired", async () => {
//       await provider.mineBlocks(11);
//       let receipt = await bns.namePreorder(
//         cases[0].namespace,
//         "bob",
//         cases[0].salt, 
//         200, { sender: cases[0].nameOwner });
//       expect(receipt.success).eq(true);
//       expect(receipt.result).eq('u41');    
//     });
//   });
// });
