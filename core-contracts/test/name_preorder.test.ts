import { Provider, ProviderRegistry, Receipt, Query } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite - NAME_PREORDER", async () => {
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

  describe("Pre-ordering the name 'bob.blockstack'", async () => {
    it("should fail if the hash of the FQN is mal-formed");

    it("should fail if Bob's balance is insufficient", async () => {
      let receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt, 
        20000000, { sender: cases[0].nameOwner });
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('4001');    
    });

    it("should succeed if Bob's balance is provisioned", async () => {
      let receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt, 
        200, { sender: cases[0].nameOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u30');    
    });

    it("should fail if the same order is being re-submitted by Bob", async () => {
      let receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt, 
        200, { sender: cases[0].nameOwner });
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('2016');    
    });

    it("should succeed if the same order is being re-submitted by Alice", async () => {
      let receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt, 
        200, { sender: alice });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u30');    
    });

    it("should succeed once claimability TTL expired", async () => {
      await provider.mineBlocks(11);
      let receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt, 
        200, { sender: cases[0].nameOwner });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u41');    
    });
  });
});
