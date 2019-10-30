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
    salt: "salt-for-alice",
    value: 42,
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

  describe("Triggering this operation", () => {
    it("should fail if 'salt' is blank");

    it("should fail if 'namespace' is blank");

    it("should fail if 'price-function' is invalid");

    it("should fail if 'renewal-rule' is invalid");
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'blockstack' initiated at block #20", async () => {

    before(async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u30');
    });

    it("should fail if TTL expired");

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

  // describe("NAME_IMPORT operation", async () => {
  //   it("should fail if 'namespace' is missing");

  //   it("should succeed on case #0", async () => {
      // let receipt = await bns.namespacePreorder(
      //   cases[0].namespace, 
      //   cases[0].salt, 
      //   cases[0].value, { sender: cases[0].namespaceOwner });


      // receipt = await bns.namespaceReady(cases[0].namespace, { sender: cases[0].namespaceOwner });

      // receipt = await bns.namePreorder(
      //   cases[0].namespace,
      //   "id",
      //   cases[0].salt, 
      //   cases[0].value, { sender: cases[0].nameOwner });

      // receipt = await bns.nameRegister(
      //   cases[0].namespace, 
      //   "id", 
      //   cases[0].salt, 
      //   cases[0].zonefile, { sender: cases[0].nameOwner });
    // });
  // });
});
