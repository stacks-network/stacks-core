import { Provider, ProviderRegistry, Receipt, Query } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite - NAME_RENEWAL", async () => {
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
    renewalRule: 0,
    nameImporter: alice,
    zonefile: "1111",
  }];

  before(async () => {
    provider = await ProviderRegistry.createProvider();
    bns = new BNSClient(provider);
    await bns.deployContract();
  });

  describe("Given a launched namespace 'id' not requiring renewing names", async () => {

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
      expect(receipt.result).eq('true');
      expect(receipt.success).eq(true);

      receipt = await bns.namespaceReady(cases[1].namespace, { sender: cases[1].namespaceOwner });
      expect(receipt.result).eq('true');
      expect(receipt.success).eq(true);

      await provider.mineBlocks(1);  
    });
  
    it("Charlie should not be able to renew 'charlie.id'", async () => {
      let receipt = await bns.namePreorder(
        cases[1].namespace,
        "charlie",
        cases[1].salt, 
        2560000, { sender: charlie });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u31');

      receipt = await bns.nameRegister(
        cases[1].namespace,
        "charlie",
        cases[1].salt,
        cases[1].zonefile, { sender: charlie });
      expect(receipt.result).eq('true');
      expect(receipt.success).eq(true);
      
      await provider.mineBlocks(5);

      receipt = await bns.nameRenewal(
        cases[1].namespace, 
        "charlie", 
        2560000, 
        null, 
        cases[1].zonefile, { sender: charlie });
      expect(receipt.result).eq('2006');
      expect(receipt.success).eq(false);
    });
  });

  describe("Given a launched namespace 'blockstack' requiring renewing names after 10 blocks", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u36');

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
  
    describe("Given a registered name 'bob.blockstack', initiated by Bob at block #21", async () => {

      before(async () => {
        let receipt = await bns.namePreorder(
          cases[0].namespace,
          "bob",
          cases[0].salt, 
          2560000, { sender: cases[0].nameOwner });
        expect(receipt.success).eq(true);
        expect(receipt.result).eq('u37');

        receipt = await bns.nameRegister(
          cases[0].namespace, 
          "bob", 
          cases[0].salt, 
          cases[0].zonefile, { sender: cases[0].nameOwner });
        expect(receipt.result).eq('true');
        expect(receipt.success).eq(true);
      });
  
      describe("When Bob is renewing 'bob.blockstack' at block #29", async () => {

        it("should succeed and set the new expiration date to #41", async () => {
          
          await provider.mineBlocks(8);

          let receipt = await bns.nameRenewal(
            cases[0].namespace, 
            "bob", 
            2560000, 
            null, 
            cases[0].zonefile, { sender: cases[0].nameOwner });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x30303030');
          expect(receipt.success).eq(true);
        });
      });

      describe("When Bob is renewing 'bob.blockstack' at block #44 (grace period)", async () => {

        it("should succeed and set the new expiration date to #51", async () => {
          
          await provider.mineBlocks(15);

          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('2009');
          expect(receipt.success).eq(false);

          receipt = await bns.nameRenewal(
            cases[0].namespace, 
            "bob", 
            2560000, 
            null, 
            cases[0].zonefile, { sender: cases[0].nameOwner });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x30303030');
          expect(receipt.success).eq(true);
        });
      });

      describe("When Bob is renewing 'bob.blockstack' at block #56 (expired)", async () => {

        it("should fail renewing", async () => {
          await provider.mineBlocks(16);

          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('2008');
          expect(receipt.success).eq(false);

          receipt = await bns.nameRenewal(
            cases[0].namespace, 
            "bob", 
            2560000, 
            null, 
            cases[0].zonefile, { sender: cases[0].nameOwner });
          expect(receipt.result).eq('2008');
          expect(receipt.success).eq(false);          
        });

        it("Dave should succeed re-registering 'bob.blockstack'", async () => {
          let receipt = await bns.namePreorder(
            cases[0].namespace,
            "bob",
            cases[0].salt, 
            2560000, { sender: dave });
          expect(receipt.success).eq(true);
          expect(receipt.result).eq('u76');
  
          receipt = await bns.nameRegister(
            cases[0].namespace, 
            "bob", 
            cases[0].salt, 
            "4444", { sender: dave });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x34343434');
          expect(receipt.success).eq(true);
        });

        it("Dave should succeed and set the new expiration date to #41", async () => {
          
          await provider.mineBlocks(8);

          let receipt = await bns.nameRenewal(
            cases[0].namespace, 
            "bob", 
            2560000, 
            bob, 
            "1111", { sender: dave });
          expect(receipt.result).eq('true');
          expect(receipt.success).eq(true);
        });

        it("should resolve as expected", async () => {
          let receipt = await bns.getNameZonefile(
            cases[0].namespace, 
            "bob", { sender: cases[0].nameOwner });
          expect(receipt.result).eq('0x31313131');
          expect(receipt.success).eq(true);
        });
      });
    });
  });
});

