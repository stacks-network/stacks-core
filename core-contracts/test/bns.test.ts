import { Provider, ProviderRegistry, Receipt } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient, PriceFunction } from "../src/bns-client";

describe("BNS Test Suite", async () => {
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
  });

  describe("NAMESPACE_PREORDER operation", async () => {
    before(async () => {
      await bns.deployContract();
    });

    it("should fail if 'hashed-namespace' is blank", async () => {
      await bns.namespacePreorder("", cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
    });

    it("should fail if 'stx-to-burn' is 0", async () => {
      await bns.namespacePreorder(cases[0].namespace, cases[0].salt, 0, { sender: cases[0].namespaceOwner });
    });

    it("should fail if Alice's balance is less than 'stx-to-burn'");

    it("should succeed when 'hashed-namespace' is a *unique 20 bytes buffer, 'stx-to-burn' > 0, and balance provisioned accordingly", async () => {
      await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, { sender: cases[0].namespaceOwner });
      // send queries
      // todo(ludo): Check Alice's STX balance
    });    

    describe("Given an existing pre-order for 'hashed-namespace' re-ordering ", () => {
      describe("When Bob submits a pre-order with the same salted hashed namespace", async () => {
        it("should succeed");  
      });
      describe("When Alice submits a pre-order with the same salted hashed namespace", () => {
        it("should fail if TTL is still valid");
  
        it("should succeed if TTL is expired");
      });  
    });
  });

      // testlib.blockstack_namespace_reveal( "test", wallets[1].addr, 52595, 250, 4, [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 10, 10, wallets[0].privkey )

  describe("NAMESPACE_REVEAL operation", async () => {
    it("should fail if 'salt' is missing");

    it("should fail if 'namespace' is missing");

    it("should fail if 'price-function' is missing");

    it("should fail if 'renewal-rule' is missing");

    it("should fail if the namespace hashing / salting does not match the entry from the preorder");

    it("should fail if the namespace hashing / salting does not match the entry from the preorder");

    it("should fail if 'price-function' is missing");

    describe("Given an existing pre-order for 'hashed-namespace' from Alice", async () => {

      let namespace = "blockstack";

      before(async () => {
        // await bns.namespacePreorder(
        //   cases[0].namespace, 
        //   cases[0].salt, 
        //   cases[0].value, { sender: cases[0].namespaceOwner });
      });
  
      it("should fail if TTL expired");

      it("should succeed if the price-function, renewal-rule, namespace and salt are valid", async () => {
        // const reveal = await bns.namespaceReveal(
        //   cases[0].namespace, 
        //   cases[0].version, 
        //   cases[0].priceFunction, 
        //   cases[0].renewalRule, 
        //   cases[0].nameImporter, { sender: cases[0].namespaceOwner });
      });
    });

    describe("Given an existing pre-order for 'hashed-namespace' from Bob", () => {
      it("should fail if TTL have not expired");

      it("should fail if TTL expired");
    });
  });

  describe("NAME_IMPORT operation", async () => {
    it("should fail if 'namespace' is missing");

    it("should succeed on case #0", async () => {
      let receipt = await bns.namespacePreorder(
        cases[0].namespace, 
        cases[0].salt, 
        cases[0].value, { sender: cases[0].namespaceOwner });
      console.log(receipt);

      receipt = await bns.namespaceReveal(
        cases[0].namespace, 
        cases[0].version, 
        cases[0].priceFunction, 
        cases[0].renewalRule, 
        cases[0].nameImporter, { sender: cases[0].namespaceOwner });
      console.log(receipt);

      receipt = await bns.namespaceReady(cases[0].namespace, { sender: cases[0].namespaceOwner });
      console.log(receipt);

      receipt = await bns.namePreorder(
        cases[0].namespace,
        "id",
        cases[0].salt, 
        cases[0].value, { sender: cases[0].nameOwner });
      console.log(receipt);

      receipt = await bns.nameRegister(
        cases[0].namespace, 
        "id", 
        cases[0].salt, 
        cases[0].zonefile, { sender: cases[0].nameOwner });
      console.log(receipt);
    });
  });

  describe("NAMESPACE_READY operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("NAME_PREORDER operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("NAME_REGISTER operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("NAME_UPDATE operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("NAME_TRANSFER operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("NAME_REVOKE operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("NAME_RENEWAL operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("SPONSORED_NAME_REGISTER_BATCH operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("SPONSORED_NAME_UPDATE operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("SPONSORED_NAME_TRANSFER operation", () => {
    it("should fail if 'namespace' is missing");
  });

  describe("SPONSORED_NAME_REVOKE operation", () => {
    it("should fail if 'namespace' is missing");
  });
});
