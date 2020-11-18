import { Provider, ProviderRegistry, Receipt, Query } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite - NAME_UPDATE", async () => {
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

  describe("Given an unlaunched namespace 'blockstack', owned by Alice", async () => {

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
    });

    it("should be possible for Alice to import a name", async () => {
      let receipt = await bns.nameImport(cases[0].namespace, "alice", "4444", { sender: alice });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');
    })

    it("should be possible for Alice to update her domain", async () => {
      let receipt = await bns.nameUpdate(
        cases[0].namespace, 
        "alice", 
        "4444", { sender: alice });
      expect(receipt.result).eq('true');
      expect(receipt.success).eq(true);
    });

    it("should not be possible for Bob to import a name", async () => {
      let receipt = await bns.nameImport(cases[0].namespace, "bob", "4444", { sender: bob });
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('1011');
    })

    it("should not resolve (namespace not launched yet)", async () => {
      let receipt = await bns.getNameZonefile(
        cases[0].namespace, 
        "alice", { sender: cases[0].nameOwner });
      expect(receipt.result).eq('1007');
      expect(receipt.success).eq(false);
    });

    describe("When Alice is launching the namespace 'blockstack' at block #20", async () => {

      before(async () => {
        let receipt = await bns.namespaceReady(cases[0].namespace, { sender: alice });
        expect(receipt.success).eq(true);
        expect(receipt.result).eq('true');  
      });

      it("Resolving 'alice.blockstack' should succeed", async () => {
        let receipt = await bns.getNameZonefile(
          cases[0].namespace, 
          "alice", { sender: cases[0].nameOwner });
        expect(receipt.result).eq('0x34343434');
        expect(receipt.success).eq(true);
      });  

      it("Charlie preordering 'charlie.blockstack' without waiting for the namespace to be launched should fail", async () => {
        let receipt = await bns.namePreorder(
          cases[0].namespace,
          "charlie",
          cases[0].salt, 
          2560000, { sender: charlie });
        expect(receipt.success).eq(true);
        expect(receipt.result).eq('u30');

        await provider.mineBlocks(1);  

        receipt = await bns.nameRegister(
          cases[0].namespace, 
          "charlie", 
          cases[0].salt, 
          cases[0].zonefile, { sender: charlie });
        expect(receipt.result).eq('2018');
        expect(receipt.success).eq(false);
      });

      it("should not resolve as expected", async () => {
        let receipt = await bns.getNameZonefile(
          cases[0].namespace, 
          "charlie", { sender: cases[0].nameOwner });
        expect(receipt.result).eq('2013');
        expect(receipt.success).eq(false);
      });

      it("Bob preordering 'bob.blockstack' waiting for the namespace to be launched should fail", async () => {

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

      describe("Bob updating his zonefile - from 1111 to 2222", async () => {

        it("should succeed", async () => {
          
          let receipt = await bns.nameUpdate(
            cases[0].namespace, 
            "bob", 
            "2222", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x32323232');
          expect(receipt.success).eq(true);
        });
      });

      describe("Charlie updating Bob's zonefile - from 2222 to 3333", async () => {

        it("should fail", async () => {
          
          let receipt = await bns.nameUpdate(
            cases[0].namespace, 
            "bob", 
            "3333", { sender: charlie });
          expect(receipt.result).eq('2006');
          expect(receipt.success).eq(false);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x32323232');
          expect(receipt.success).eq(true);
        });
      });

    });
  });
});

