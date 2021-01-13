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
    }];
  
    beforeEach(async () => {
      const allocations = [{
          principal: alice,
          amount: 10_000_000_000_000_000
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
  
    it("Testing namespace prices", async () => {
        var receipt = await bns.getNamespacePrice("a");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u640000000000)`);
      
        var receipt = await bns.getNamespacePrice("1");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u640000000000)`);

        var receipt = await bns.getNamespacePrice("ab");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u64000000000)`);

        var receipt = await bns.getNamespacePrice("abc");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u64000000000)`);

        var receipt = await bns.getNamespacePrice("abcd");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u6400000000)`);

        var receipt = await bns.getNamespacePrice("abcde");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u6400000000)`);

        var receipt = await bns.getNamespacePrice("abcdef");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u6400000000)`);

        var receipt = await bns.getNamespacePrice("abcdefg");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u6400000000)`);

        var receipt = await bns.getNamespacePrice("abcdefgh");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u640000000)`);

        var receipt = await bns.getNamespacePrice("abcdefghi");
        expect(receipt.success).eq(true);
        expect(receipt.result).include(`(ok u640000000)`);
    });
  });