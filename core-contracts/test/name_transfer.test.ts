import { Provider, ProviderRegistry, Receipt, Query } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite - NAME_TRANSFER", async () => {
  let bns: BNSClient;
  let provider: Provider;

  const addresses = [
    "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
    "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
    "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR",
    "SPMQEKN07D1VHAB8XQV835E3PTY3QWZRZ5H0DM36"
  ];
  const alice = addresses[0];
  const bob = addresses[1];
  const charlie = addresses[2];
  const dave = addresses[3];

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
    renewalRule: 4294967295,
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

      receipt = await bns.namespaceReady(cases[0].namespace, { sender: cases[0].nameImporter });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');

      await provider.mineBlocks(1);  
    });
  
    describe("Given some names 'bob.blockstack' and 'charlie.blockstack' registered at block #21", async () => {

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

        receipt = await bns.namePreorder(
          cases[0].namespace,
          "charlie",
          cases[0].salt, 
          2560000, { sender: charlie });
        expect(receipt.success).eq(true);
        expect(receipt.result).eq('u31');

        receipt = await bns.nameRegister(
          cases[0].namespace, 
          "charlie", 
          cases[0].salt, 
          cases[0].zonefile, { sender: charlie });
        expect(receipt.result).eq('true');
        expect(receipt.success).eq(true);

      });
  
      describe("Charlie transfering 'bob.blockstack' on Bob's behalf", async () => {
        it("should fail", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "bob", 
            charlie,
            "3333", { sender: charlie });
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

      describe("Bob transfering 'bob.blockstack' to Dave", async () => {

        it("should succeed", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "bob", 
            dave,
            "3333", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x33333333');
          expect(receipt.success).eq(true);
        });
      });

      describe("Charlie transfering 'charlie.blockstack' to Dave", async () => {

        it("should fail since Dave already received 'bob.blockstack'", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "charlie", 
            dave,
            "3333", { sender: charlie });
          expect(receipt.result).eq('3001');
          expect(receipt.success).eq(false);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "charlie", { sender: charlie });
          expect(receipt.result).eq('0x30303030');
          expect(receipt.success).eq(true);
        });
      });

      describe("Charlie transfering 'charlie.blockstack' to Bob", async () => {

        it("should succeed", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "charlie", 
            bob,
            "4444", { sender: charlie });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "charlie", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x34343434');
          expect(receipt.success).eq(true);
        });
      });

      describe("Bob transfering 'charlie.blockstack' back to Charlie", async () => {
        it("should succeed", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "charlie", 
            charlie,
            null, { sender: bob });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "charlie", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x00');
          expect(receipt.success).eq(true);
        });

        it("Bob should not be able to update 'charlie.blockstack'", async () => {
          let receipt = await bns.nameUpdate(
            cases[0].namespace, 
            "charlie", 
            "4444", { sender: bob });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });  

        it("Charlie should be able to update 'charlie.blockstack'", async () => {
          let receipt = await bns.nameUpdate(
            cases[0].namespace, 
            "charlie", 
            "2222", { sender: charlie });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });  
      });

      describe("Dave transfering 'bob.blockstack' back to Bob", async () => {
        it("should succeed", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "bob", 
            bob,
            null, { sender: dave });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x00');
          expect(receipt.success).eq(true);
        });

        it("Bob should be able to update its zonefile", async () => {
          let receipt = await bns.nameUpdate(
            cases[0].namespace, 
            "bob", 
            "3333", { sender: bob });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });  
      });

      describe("Alice trying to transfer 'alice.blockstack'", async () => {
        it("should fail, since 'alice.blockstack' was imported", async () => {
          let receipt = await bns.nameTransfer(
            cases[0].namespace, 
            "alice", 
            bob,
            "4444", { sender: cases[0].nameImporter });
          expect(receipt.result).eq('2006');
          expect(receipt.success).eq(false);
        });
      });

    });
  });
});

