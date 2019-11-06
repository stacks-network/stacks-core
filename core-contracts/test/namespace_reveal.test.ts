import { Provider, ProviderRegistry, Receipt, Query } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite - NAMESPACE_REVEAL", async () => {
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

  it("Revealing a non-existing pre-order should fail", async () => {
    let receipt = await bns.namespaceReveal(
      cases[0].namespace, 
      cases[0].version, 
      cases[0].salt,
      cases[0].priceFunction, 
      cases[0].renewalRule, 
      cases[0].nameImporter, { sender: cases[0].namespaceOwner });
    expect(receipt.success).eq(false);
    expect(receipt.result).eq('1001');
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'id' initiated at block #31, resubmitting the same pre-order", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u30');
    });

    it("should fail", async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('1003');
    });
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'blockstack' initiated at block #20, revealing the namespace", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u30');
    });

    it("should fail if the sender changed", async () => {
      let receipt = await bns.namespaceReveal(
        cases[0].namespace, 
        cases[0].version, 
        cases[0].salt,
        cases[0].priceFunction, 
        cases[0].renewalRule, 
        cases[0].nameImporter, { sender: bob });
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('1001');
    });

    it("should fail if TTL expired", async () => {
      await provider.mineBlocks(11);
      let receipt = await bns.namespaceReveal(
        cases[0].namespace, 
        cases[0].version, 
        cases[0].salt,
        cases[0].priceFunction, 
        cases[0].renewalRule, 
        cases[0].nameImporter, { sender: bob });
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('1001');
    });
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'blockstack' initiated at block #31, revealing the namespace", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u41');
    });


    it("should succeed if the price-function, renewal-rule, namespace and salt are valid", async () => {
      let receipt = await bns.namespaceReveal(
        cases[0].namespace, 
        cases[0].version, 
        cases[0].salt,
        cases[0].priceFunction, 
        cases[0].renewalRule, 
        cases[0].nameImporter, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');
    });
  });

  describe("Given a pre-order, too cheap, from Bob for the namespace 'id' initiated at block #31, revealing the namespace", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, 96, { sender: bob });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u41');
    });

    it("should fail", async () => {
      let receipt = await bns.namespaceReveal(
        cases[1].namespace, 
        cases[1].version, 
        cases[1].salt,
        cases[1].priceFunction, 
        cases[1].renewalRule, 
        cases[1].nameImporter, { sender: bob });
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('1012');
    });
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'id' initiated at block #31, revealing the namespace", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u41');
    });

    it("should succeed if the price-function, renewal-rule, namespace and salt are valid", async () => {
      let receipt = await bns.namespaceReveal(
        cases[1].namespace, 
        cases[1].version, 
        cases[1].salt,
        cases[1].priceFunction, 
        cases[1].renewalRule, 
        cases[1].nameImporter, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');
    });
  });

});
