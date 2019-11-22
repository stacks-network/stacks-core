import { Provider, ProviderRegistry, Receipt, Query } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite - NAME_IMPORT", async () => {
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
    nameImporter: bob,
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

  describe("Given a launched namespace 'blockstack', owned by Alice, where Bob is nameImporter", async () => {

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
      await provider.mineBlocks(1);  
    });

    it("Charlie trying to import 'alpha.blockstack' should fail", async () => {
      let receipt = await bns.nameImport(cases[0].namespace, "alpha", cases[0].zonefile, { sender: charlie })
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('1011');
    });

    it("Bob trying to import 'alpha.blockstack' should succeed", async () => {
      let receipt = await bns.nameImport(cases[0].namespace, "alpha", cases[0].zonefile, { sender: bob })
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');
    });

    it("Resolving an imported name should fail if the namespace is not ready", async () => {
      let receipt = await bns.getNameZonefile(
        cases[0].namespace, 
        "alpha", { sender: cases[0].nameOwner });
      expect(receipt.result).eq('1007');
      expect(receipt.success).eq(false);
    });

    it("Bob trying to import 'beta.blockstack' should fail after the launch of the domain", async () => {
      let receipt = await bns.namespaceReady(cases[0].namespace, { sender: bob });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');
      await provider.mineBlocks(1);  

      receipt = await bns.nameImport(cases[0].namespace, "beta", cases[0].zonefile, { sender: bob })
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('1014');
    });

    it("Resolving an imported name should succeed if the namespace is ready", async () => {
      let receipt = await bns.getNameZonefile(
        cases[0].namespace, 
        "alpha", { sender: bob });
      expect(receipt.result).eq('0x30303030');
      expect(receipt.success).eq(true);
    });

    it("Charlie trying to register 'alpha.blockstack' should fail", async () => {
      let receipt = await bns.namePreorder(
        cases[0].namespace,
        "alpha",
        cases[0].salt, 
        160000, { sender: charlie });
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('u32');

      receipt = await bns.nameRegister(
        cases[0].namespace, 
        "alpha", 
        cases[0].salt, 
        cases[0].zonefile, { sender: charlie });
      expect(receipt.result).eq('2004');
      expect(receipt.success).eq(false);
    });

    it("Charlie trying to renew 'alpha.blockstack' should fail", async () => {
      let receipt = await bns.nameRenewal(cases[0].namespace, "alpha", 160000, charlie, cases[0].zonefile, { sender: charlie })
      expect(receipt.success).eq(false);
      expect(receipt.result).eq('2006');
    });
  
    it("Bob trying to renew 'alpha.blockstack' should succeed", async () => {
      let receipt = await bns.nameRenewal(cases[0].namespace, "alpha", 160000, charlie, "6666", { sender: bob })
      expect(receipt.success).eq(true);
      expect(receipt.result).eq('true');
    });

    it("Resolving an imported name should fail after expiration", async () => {
      await provider.mineBlocks(20);  

      let receipt = await bns.getNameZonefile(
        cases[0].namespace, 
        "alpha", { sender: cases[0].nameOwner });
      expect(receipt.result).eq('2008');
      expect(receipt.success).eq(false);
    });
  });
});
