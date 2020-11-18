import { Provider, ProviderRegistry, Receipt, Query } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite - NAME_REVOKE", async () => {
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
      buckets: [7, 6, 5, 4, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
      base: 4,
      coeff: 250,
      noVoyelDiscount: 4,
      nonAlphaDiscount: 4,
    },
    renewalRule: 10,
    nameImporter: alice,
    zonefile: "0000",
  }, {
    namespace: "id",
    version: 1,
    salt: "0000",
    value: 9600,
    namespaceOwner: alice,
    nameOwner: bob,
    priceFunction: {
      buckets: [6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      base: 4,
      coeff: 250,
      noVoyelDiscount: 20,
      nonAlphaDiscount: 20,
    },
    renewalRule: 52595,
    nameImporter: alice,
    zonefile: "1111",
  }];

  before(async () => {
    provider = await ProviderRegistry.createProvider();
    bns = new BNSClient(provider);
    await bns.deployContract();
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

      receipt = await bns.nameImport(cases[0].namespace, "alice", cases[0].zonefile, { sender: cases[0].nameImporter })
      expect(receipt.success).eq(true);

      receipt = await bns.namespaceReady(cases[0].namespace, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');

      await provider.mineBlocks(1);  
    });
  
    describe("Given a registered name 'bob.blockstack', initiated by Bob at block #21", async () => {

      before(async () => {
        let receipt = await bns.namePreorder(
          cases[0].namespace,
          "bob",
          cases[0].salt, 
          2560000, { sender: cases[0].nameOwner });
        expect(receipt.success).eq(true);
        expect(receipt.result).eq('u31');

        receipt = await bns.nameRegister(
          cases[0].namespace, 
          "bob", 
          cases[0].salt, 
          cases[0].zonefile, { sender: cases[0].nameOwner });
        expect(receipt.result).eq('true');
        expect(receipt.success).eq(true);
      });
  
      describe("Charlie revoking 'bob.blockstack' on Bob's behalf", async () => {

        it("should fail", async () => {
          
          let receipt = await bns.nameRevoke(
            cases[0].namespace, 
            "bob", { sender: charlie });
          expect(receipt.result).eq('2006');
          expect(receipt.success).eq(false);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x30303030');
          expect(receipt.success).eq(true);
        });
      });

      describe("Bob revoking 'bob.blockstack'", async () => {

        it("should succeed", async () => {
          
          let receipt = await bns.nameRevoke(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should not be able to resolve", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('2014');
          expect(receipt.success).eq(false);
        });

        it("Bob trying to update 'bob.blockstack' should fail", async () => {
          let receipt = await bns.nameUpdate(
            cases[0].namespace, 
            "bob", 
            "4444", { sender: bob });
          expect(receipt.result).eq('2014');
          expect(receipt.success).eq(false);
        });

        it("Bob trying to transfer 'bob.blockstack' should fail", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "bob", 
            charlie,
            "4444", { sender: bob });
          expect(receipt.result).eq('2014');
          expect(receipt.success).eq(false);
        });

        it("Bob trying to register 'bob.blockstack' should fail", async () => {
          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "bob",
            "salt#2", 
            2560000, { sender: bob });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u31');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bob", 
            "salt#2",
            cases[0].zonefile, { sender: bob });
          expect(receipt.result).eq('2004');
          expect(receipt.success).eq(false);
        });

        it("Bob trying to renew 'bob.blockstack' should fail", async () => {
          let receipt = await bns.nameRenewal(
            cases[0].namespace, 
            "bob", 
            2560000, 
            bob,
            "4444", { sender: bob });
          expect(receipt.result).eq('2014');
          expect(receipt.success).eq(false);
        });

        it("Alice trying to renew 'alice.blockstack' should succeed", async () => {
          await provider.mineBlocks(10);

          let receipt = await bns.nameRenewal(
            cases[0].namespace, 
            "alice", 
            2560000, 
            alice,
            "6666", { sender: alice });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("Bob trying to register 'bob.blockstack', once expired, should succeed", async () => {
          await provider.mineBlocks(10);

          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "bob",
            "salt#2", 
            2560000, { sender: bob });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u51');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bob", 
            "salt#2",
            cases[0].zonefile, { sender: bob });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

      });
    
      describe("Charlie revoking 'alice.blockstack' on Alice's behalf (imported name)", async () => {

        it("should fail", async () => {
          let receipt = await bns.nameRevoke(
            cases[0].namespace, 
            "alice", { sender: charlie });
          expect(receipt.result).eq('2006');
          expect(receipt.success).eq(false);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "alice", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x36363636');
          expect(receipt.success).eq(true);
        });
      });

      describe("Alice revoking 'alice.blockstack' (imported name)", async () => {

        it("should succeed", async () => {
          let receipt = await bns.nameRevoke(
            cases[0].namespace, 
            "alice", { sender: alice });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should stop resolving", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "alice", { sender: alice });
          expect(receipt.result).eq('2014');
          expect(receipt.success).eq(false);
        });

        it("Alice trying to update 'alice.blockstack' should fail", async () => {
          let receipt = await bns.nameUpdate(
            cases[0].namespace, 
            "alice", 
            "4444", { sender: alice });
          expect(receipt.result).eq('2014');
          expect(receipt.success).eq(false);
        });

        it("Alice trying to transfer 'alice.blockstack' should fail", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "alice", 
            charlie,
            "4444", { sender: alice });
          expect(receipt.result).eq('2014');
          expect(receipt.success).eq(false);
        });

        it("Alice trying to renew 'alice.blockstack' should fail", async () => {
          let receipt = await bns.nameRenewal(
            cases[0].namespace, 
            "alice", 
            2560000, 
            alice,
            "4444", { sender: alice });
          expect(receipt.result).eq('2014');
          expect(receipt.success).eq(false);
        });

        it("Alice trying to register 'alice.blockstack' should fail", async () => {
          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "alice",
            "salt#2", 
            2560000, { sender: alice });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u51');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "alice", 
            "salt#2",
            cases[0].zonefile, { sender: alice });
          expect(receipt.result).eq('2004');
          expect(receipt.success).eq(false);
        });
      });
    });
  });
});

