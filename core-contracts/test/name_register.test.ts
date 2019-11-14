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

  describe("Given an unlaunched namespace 'id', owned by Alice", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u30');

      receipt = await bns.namespaceReveal(
        cases[1].namespace, 
        cases[1].version, 
        cases[1].salt,
        cases[1].priceFunction, 
        cases[1].renewalRule, 
        cases[1].nameImporter, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');
    });

    describe("Pre-ordering and Revealing the name 'baobab.blockstack'", async () => {
      it("should fail, since the namespace isn't launched", async () => {
        let receipt = await bns.namePreorder(
          cases[1].namespace, 
          "baobab",
          cases[1].salt, 
          100, { sender: bob });
        expect(receipt.result).eq('u30');
        expect(receipt.success).eq(true);

        receipt = await bns.nameRegister(
          cases[1].namespace, 
          "baobab", 
          cases[1].salt, 
          cases[1].zonefile, { sender: bob });
        expect(receipt.result).eq('1007');    
        expect(receipt.success).eq(false);
      });
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

      await provider.mineBlocks(1);  
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
  
    describe("Given a pre-order of the name 'bub.blockstack', burning 2559999 STX instead of 2560000 STX, Revealing the name", async () => {
      before(async () => {

        let receipt = await bns.namePreorder(
          cases[0].namespace,
          "bub",
          cases[0].salt, 
          2559999, { sender: bob });
        expect(receipt.success).eq(true);
        expect(receipt.result).eq('u31');
      });

      it("should fail", async () => {
        let receipt = await bns.nameRegister(
          cases[0].namespace, 
          "bub", 
          cases[0].salt, 
          cases[0].zonefile, { sender: bob });
        expect(receipt.result).eq('2007');    
        expect(receipt.success).eq(false);
      });
    });

    describe("Given an existing pre-order of the name 'Bob.blockstack', initiated by Bob at block #21", async () => {

      before(async () => {
        let receipt = await bns.namePreorder(
          cases[0].namespace,
          "Bob",
          cases[0].salt, 
          2560000, { sender: cases[0].nameOwner });
        expect(receipt.success).eq(true);
        expect(receipt.result).eq('u31');
      });
  
      it("Bob registering the name 'Bob.blockstack' should fail", async () => {
        let receipt = await bns.nameRegister(
          cases[0].namespace, 
          "Bob", 
          cases[0].salt, 
          cases[0].zonefile, { sender: cases[0].nameOwner });
        expect(receipt.result).eq('2022');
        expect(receipt.success).eq(false);
      });
    });

    describe("Given an existing pre-order of the name 'bob.blockstack', initiated by Bob at block #21", async () => {

      before(async () => {
        let receipt = await bns.namePreorder(
          cases[0].namespace,
          "bob",
          cases[0].salt, 
          2560000, { sender: cases[0].nameOwner });
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

          receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x30303030');
          expect(receipt.success).eq(true);
        });

        it("should fail registering twice", async () => {
          let receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bob", 
            cases[0].salt, 
            cases[0].zonefile, { sender: cases[0].nameOwner });
          expect(receipt.result).eq('2004');
          expect(receipt.success).eq(false);
        });

      });

      describe("Charlie registering 'bob.blockstack'", async () => {

        it("should fail", async () => {

          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "bob",
            cases[0].salt, 
            2560000, { sender: charlie });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u31');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bob", 
            cases[0].salt, 
            cases[0].zonefile, { sender: charlie });
          expect(receipt.result).eq('2004');
          expect(receipt.success).eq(false);
        });
      });

      // todo(ludo): investigate the case where 'name.namespace' was preordered while being unavailable
      // and then became available
      describe("Bob registering a second name 'bobby.blockstack'", async () => {

        it("should fail if 'bob.blockstack' is not expired", async () => {
          await provider.mineBlocks(1);

          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "bobby",
            cases[0].salt, 
            160000, { sender: cases[0].nameOwner });
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
            160000, { sender: cases[0].nameOwner });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u42');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bobby", 
            cases[0].salt, 
            cases[0].zonefile, { sender: cases[0].nameOwner });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);

          receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bobby", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x30303030');
          expect(receipt.success).eq(true);
        });
      });

      describe("Charlie registering 'bob.blockstack'", async () => {

        it("should succeed once 'bob.blockstack' is expired", async () => {

          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "bob",
            cases[0].salt, 
            2560000, { sender: charlie });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u42');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bob", 
            cases[0].salt, 
            "AAAA", { sender: charlie });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);

          receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x41414141');
          expect(receipt.success).eq(true);
        });
      });

    });
  });
});

