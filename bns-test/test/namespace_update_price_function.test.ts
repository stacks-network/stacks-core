import {
    NativeClarityBinProvider
  } from "@blockstack/clarity";
  import {
    expect
  } from "chai";
  import {
    getTempFilePath
  } from "@blockstack/clarity/lib/utils/fsUtil";
  import {
    getDefaultBinaryFilePath
  } from "@blockstack/clarity-native-bin";
  import {
    BNSClient,
    PriceFunction
  } from "../src/bns-client";
  import {
    mineBlocks
  } from "./utils";
  
  describe("BNS Test Suite - NAMESPACE_UPDATE_PRICE_FUNCTION", () => {
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
      const allocations = [{
          principal: alice,
          amount: 10_000_000_000_000
        },
        {
          principal: bob,
          amount: 10_000_000_000_000
        },
        {
          principal: charlie,
          amount: 10_000_000_000_000
        },
        {
          principal: dave,
          amount: 10_000_000_000_000
        },
      ]
      const binFile = getDefaultBinaryFilePath();
      const dbFileName = getTempFilePath();
      provider = await NativeClarityBinProvider.create(allocations, dbFileName, binFile);
      bns = new BNSClient(provider);
      await bns.deployContract();
    });
  
    it("Given a revealed pre-order from Alice for the namespace 'blockstack' initiated at block #20", async () => {
      var receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');
  
      receipt = await bns.namespaceReveal(
        cases[0].namespace,
        cases[0].salt,
        cases[0].priceFunction,
        cases[0].renewalRule,
        cases[0].nameImporter, {
          sender: cases[0].namespaceOwner
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');
  
      // Launching the namespace
      // should succeed if the namespace has not already been launched, and revealed less than a year ago (todo: fix TTL)
      receipt = await bns.namespaceReady(cases[0].namespace, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');
  
      receipt = await bns.getNamePrice(cases[0].namespace, "a");
      expect(receipt.success).eq(true);
      // curl https://core.blockstack.org/v2/prices/names/a.blockstack
      expect(receipt.result).include(`(ok u20)`); 

      let priceFunctionUpdate1 = {
        buckets: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        base: 1,
        coeff: 4, // <- update
        noVowelDiscount: 0,
        nonAlphaDiscount: 0,
      };

      // Updating the price function should succeed
      receipt = await bns.namespaceUpdatePriceFunction(cases[0].namespace, 
        priceFunctionUpdate1,
        {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');

      // New price should be 2x what we had before
      receipt = await bns.getNamePrice(cases[0].namespace, "a");
      expect(receipt.success).eq(true);
      expect(receipt.result).include(`(ok u40)`); 

        // Now, let's give up on our ability to update the price function
      receipt = await bns.namespaceRevokePriceFunctionUpdates(cases[0].namespace, 
        {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');

      let priceFunctionUpdate2 = {
        buckets: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        base: 1,
        coeff: 8, // <- update
        noVowelDiscount: 0,
        nonAlphaDiscount: 0,
      };

      // Updating the price function should fail
      receipt = await bns.namespaceUpdatePriceFunction(cases[0].namespace, 
        priceFunctionUpdate2,
        {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('1011');

      // Prices should stay the same
      var receipt = await bns.getNamePrice(cases[0].namespace, "a");
      expect(receipt.success).eq(true);
      // curl https://core.blockstack.org/v2/prices/names/a.blockstack
      expect(receipt.result).include(`(ok u40)`); 
    });
  });