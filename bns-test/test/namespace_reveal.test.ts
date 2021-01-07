import { NativeClarityBinProvider } from "@blockstack/clarity";
import { expect } from "chai";
import { getTempFilePath } from "@blockstack/clarity/lib/utils/fsUtil";
import { getDefaultBinaryFilePath } from "@blockstack/clarity-native-bin";
import { BNSClient, PriceFunction } from "../src/bns-client";
import { mineBlocks } from "./utils";

describe("BNS Test Suite - NAMESPACE_REVEAL", () => {
  let bns: BNSClient;
  let provider: NativeClarityBinProvider;

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
    value: 640000000,
    namespaceOwner: alice,
    nameOwner: bob,
    priceFunction: {
      buckets: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
      base: 1,
      coeff: 2,
      noVowelDiscount: 0,
      nonAlphaDiscount: 0,
    },
    renewalRule: 1,
    nameImporter: alice,
    zonefile: "LOREM IPSUM DOLOR SIT AMET",
  }, {
    namespace: "id",
    version: 1,
    salt: "0000",
    value: 64000000000,
    namespaceOwner: alice,
    nameOwner: bob,
    priceFunction: {
      buckets: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
      base: 1,
      coeff: 2,
      noVowelDiscount: 0,
      nonAlphaDiscount: 0,
    },
    renewalRule: 1,
    nameImporter: alice,
    zonefile: "LOREM IPSUM DOLOR SIT AMET",
  }];

  beforeEach(async () => {
    const allocations = [
      { principal: alice, amount: 10_000_000_000_000 },
      { principal: bob, amount: 10_000_000_000_000 },
      { principal: charlie, amount: 10_000_000_000_000 },
      { principal: dave, amount: 10_000_000_000_000 },
    ]
    const binFile = getDefaultBinaryFilePath();
    const dbFileName = getTempFilePath();
    provider = await NativeClarityBinProvider.create(allocations, dbFileName, binFile);
    bns = new BNSClient(provider);
    await bns.deployContract();
  });


  it("Revealing a non-existing pre-order should fail", async () => {
    let receipt = await bns.namespaceReveal(
      cases[0].namespace, 
      cases[0].salt,
      cases[0].priceFunction, 
      cases[0].renewalRule, 
      cases[0].nameImporter, { sender: cases[0].namespaceOwner });
    expect(receipt.success).eq(false);
    expect(receipt.error).include('1001');
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'id' initiated at block #31, resubmitting the same pre-order", () => {

    beforeEach(async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');
    });

    it("should fail", async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('1003');
    });
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'blockstack' initiated at block #20, revealing the namespace", () => {

    beforeEach(async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');
    });

    it("should fail if the sender changed", async () => {
      let receipt = await bns.namespaceReveal(
        cases[0].namespace, 
        cases[0].salt,
        cases[0].priceFunction, 
        cases[0].renewalRule, 
        cases[0].nameImporter, { sender: bob });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('1001');
    });

    it("should fail if TTL expired", async () => {
      await mineBlocks(bns, 11);
      let receipt = await bns.namespaceReveal(
        cases[0].namespace, 
        cases[0].salt,
        cases[0].priceFunction, 
        cases[0].renewalRule, 
        cases[0].nameImporter, { sender: bob });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('1001');
    });
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'blockstack' initiated at block #31, revealing the namespace", () => {

    beforeEach(async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');
    });


    it("should succeed if the price-function, lifetime, namespace and salt are valid", async () => {
      let receipt = await bns.namespaceReveal(
        cases[0].namespace, 
        cases[0].salt,
        cases[0].priceFunction, 
        cases[0].renewalRule, 
        cases[0].nameImporter, { sender: cases[0].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');
    });
  });

  describe("Given a pre-order, too cheap, from Bob for the namespace 'id' initiated at block #31, revealing the namespace", () => {

    beforeEach(async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, 96, { sender: bob });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');
    });

    it("should fail", async () => {
      let receipt = await bns.namespaceReveal(
        cases[1].namespace, 
        cases[1].salt,
        cases[1].priceFunction, 
        cases[1].renewalRule, 
        cases[1].nameImporter, { sender: bob });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('1012');
    });
  });

  describe("Given an existing, valid pre-order from Alice for the namespace 'id' initiated at block #31, revealing the namespace", () => {

    beforeEach(async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');
    });

    it("should succeed if the price-function, lifetime, namespace and salt are valid", async () => {
      let receipt = await bns.namespaceReveal(
        cases[1].namespace, 
        cases[1].salt,
        cases[1].priceFunction, 
        cases[1].renewalRule, 
        cases[1].nameImporter, { sender: cases[1].namespaceOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');
    });
  });

});
