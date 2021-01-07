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

describe("BNS Test Suite - NAMESPACE_PREORDER", () => {
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


  describe("Triggering this operation", () => {

    it("should fail if 'hashed-namespace' is blank", async () => {
      // Should fail when using the helper
      let error;
      try {
        await bns.namespacePreorder("", cases[0].salt, cases[0].value, {
          sender: cases[0].namespaceOwner
        });
      } catch (e) {
        error = e;
      }
      expect(error).instanceOf(Error);
      expect(error.message).eq("Namespace can't be empty");

      // Should fail when bypassing the helper
      const tx = bns.createTransaction({
        method: {
          name: "namespace-preorder",
          args: [`0x`, `u${cases[0].value}`]
        }
      });
      await tx.sign(cases[0].namespaceOwner);
      const res = await bns.submitTransaction(tx);
      expect(res.success).eq(false);
      expect(res.error).include('1015');
    });

    it("should fail if 'stx-to-burn' is 0", async () => {
      // Should fail when using the helper
      let error;
      try {
        await bns.namespacePreorder(cases[0].namespace, cases[0].salt, 0, {
          sender: cases[0].namespaceOwner
        });
      } catch (e) {
        error = e;
      }
      expect(error).instanceOf(Error);
      expect(error.message).eq("STX should be non-zero positive");

      // Should fail when bypassing the helper
      const tx = bns.createTransaction({
        method: {
          name: "namespace-preorder",
          args: [`0x09438924095489319301`, `u0`]
        }
      });
      await tx.sign(cases[0].namespaceOwner);
      const res = await bns.submitTransaction(tx);
      expect(res.success).eq(false);
      expect(res.error).include('1015');
    });

    it("should fail if Alice can't afford paying the fee", async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, 20000000000000, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('4001');
    });

    it("should succeed when Alice pre-orders 'blockstack', 'stx-to-burn' = 96 (balance ok)", async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');
    });

    it("should succeed when Alice pre-orders 'id', 'stx-to-burn' = 9600 (balance ok)", async () => {
      let receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, {
        sender: cases[1].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');
    });

    // Given an existing pre-order for 'blockstack' registered by Alice
    // When Bob submits a pre-order with the same salted hashed namespace

    it("should succeed", async () => {
      var receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
        sender: bob
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u146');

      // When Alice submits a pre-order with the same salted hashed namespace
      // should fail if TTL is still valid
      receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u147');

      // Let's mine 5 blocks and check
      await mineBlocks(bns, 5);
      receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('1003');

      // Let's mine 136 more blocks and check (TTL = 144)
      await mineBlocks(bns, 136);
      receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
        sender: bob
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u290'); // 20 blocks simulated initially + 11 blocks simulated + TTL
    });

  });
});