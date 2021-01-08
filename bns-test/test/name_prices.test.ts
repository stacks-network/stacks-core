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
  
  describe("BNS Test Suite - Namespace prices", () => {
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
        buckets: [7, 6, 5, 4, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        base: 4,
        coeff: 250,
        noVowelDiscount: 4,
        nonAlphaDiscount: 4,
      },
      renewalRule: 4294967295,
      nameImporter: alice,
      zonefile: "0000",
    }, {
      namespace: "id",
      version: 1,
      salt: "0000",
      value: 64000000000,
      namespaceOwner: alice,
      nameOwner: bob,
      priceFunction: {
        buckets: [6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        base: 4,
        coeff: 250,
        noVowelDiscount: 20,
        nonAlphaDiscount: 20,
      },
      renewalRule: 52595,
      nameImporter: alice,
      zonefile: "1111",
    },
    {
      namespace: "btc",
      version: 1,
      salt: "0000",
      value: 64000000000,
      namespaceOwner: alice,
      nameOwner: bob,
      priceFunction: {
        buckets: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        base: 1000,
        coeff: 200,
        noVowelDiscount: 1,
        nonAlphaDiscount: 1,
      },
      renewalRule: 52595,
      nameImporter: alice,
      zonefile: "2222",
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
  
    it("Test btc namespace price", async () => {
      var receipt = await bns.namespacePreorder(cases[2].namespace, cases[2].salt, cases[2].value, {
        sender: cases[2].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');

      receipt = await bns.namespaceReveal(
          cases[2].namespace,
          cases[2].salt,
          cases[2].priceFunction,
          cases[2].renewalRule,
          cases[2].nameImporter, {
          sender: cases[2].namespaceOwner
          });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');

      receipt = await bns.namespaceReady(cases[2].namespace, {
          sender: cases[2].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');

      var receipt = await bns.getNamePrice(cases[2].namespace, "a");
      expect(receipt.success).eq(true);
      // 2 STX
      expect(receipt.result).include(`(ok u2000000)`); 

      var receipt = await bns.getNamePrice(cases[2].namespace, "abcdefghijk123456789");
      expect(receipt.success).eq(true);
      // 2 STX
      expect(receipt.result).include(`(ok u2000000)`);

    });

    it("Testing name prices", async () => {
        // Given a launched namespace 'blockstack', owned by Alice
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

        receipt = await bns.namespaceReady(cases[0].namespace, {
            sender: cases[0].namespaceOwner
        });
        expect(receipt.success).eq(true);
        expect(receipt.result).include('true');

        // Price function used:
        // buckets: [7, 6, 5, 4, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        // base: 4,
        // coeff: 250,
        // noVowelDiscount: 4,
        // nonAlphaDiscount: 4,      

        var receipt = await bns.getNamePrice(cases[0].namespace, "a");
        expect(receipt.success).eq(true);
        // curl https://core.blockstack.org/v2/prices/names/a.blockstack
        expect(receipt.result).include(`(ok u40960000)`); 
      
        var receipt = await bns.getNamePrice(cases[0].namespace, "1");
        expect(receipt.success).eq(true);
        // curl https://core.blockstack.org/v2/prices/names/1.blockstack
        expect(receipt.result).include(`(ok u10240000)`);

        var receipt = await bns.getNamePrice(cases[0].namespace, "ab");
        expect(receipt.success).eq(true);
        // curl https://core.blockstack.org/v2/prices/names/ab.blockstack
        expect(receipt.result).include(`(ok u10240000)`);

        var receipt = await bns.getNamePrice(cases[0].namespace, "abc");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u2560000)`);

        var receipt = await bns.getNamePrice(cases[0].namespace, "abcd");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u640000)`);

        var receipt = await bns.getNamePrice(cases[0].namespace, "abcde");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u160000)`);

        var receipt = await bns.getNamePrice(cases[0].namespace, "abcdef");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u40000)`);

        var receipt = await bns.getNamePrice(cases[0].namespace, "abcdefg");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u10000)`);

        var receipt = await bns.getNamePrice(cases[0].namespace, "abcdefgh");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u10000)`);

        var receipt = await bns.getNamePrice(cases[0].namespace, "abcdefghi");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u10000)`);
    });
  });