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

describe("BNS Test Suite - NAME_PREORDER", () => {
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
        amount: 10_000_000
      },
      {
        principal: charlie,
        amount: 10_000_000
      },
      {
        principal: dave,
        amount: 10_000_000
      },
    ]
    const binFile = getDefaultBinaryFilePath();
    const dbFileName = getTempFilePath();
    provider = await NativeClarityBinProvider.create(allocations, dbFileName, binFile);
    bns = new BNSClient(provider);
    await bns.deployContract();
  });

  describe("Pre-ordering the name 'bob.blockstack'", () => {
    // should fail if the hash of the FQN is mal-formed");

    it("should fail if Bob's balance is insufficient", async () => {

      await mineBlocks(bns, 20);

      var receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt,
        20000000, {
          sender: cases[0].nameOwner
        });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('4001');

      // should succeed if Bob's balance is provisioned
      receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt,
        200, {
          sender: cases[0].nameOwner
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u167');

      // should fail if the same order is being re-submitted by Bob
      receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt,
        200, {
          sender: cases[0].nameOwner
        });
      expect(receipt.success).eq(false);
      expect(receipt.error).include('2016');

      // should succeed if the same order is being re-submitted by Alice
      receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt,
        200, {
          sender: alice
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u169');


      // should succeed once claimability TTL expired
      await mineBlocks(bns, 154);
      receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt,
        200, {
          sender: cases[0].nameOwner
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u324');
    });
  });
});