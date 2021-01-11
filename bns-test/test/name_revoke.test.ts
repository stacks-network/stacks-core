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

describe("BNS Test Suite - NAME_REVOKE", () => {
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
    renewalRule: 10,
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

  describe("Given a launched namespace 'blockstack', owned by Alice", () => {

    it("Given a registered name 'bob.blockstack', initiated by Bob at block #21", async () => {
      let block_height = 2;
      let namespace_preorder_ttl = 10;
      let name_preorder_ttl = 10;

      var receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include(`${block_height+namespace_preorder_ttl}`);

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
      block_height += 1;

      receipt = await bns.nameImport(cases[0].namespace, "alice", cases[0].nameImporter, cases[0].zonefile, {
        sender: cases[0].nameImporter
      })
      expect(receipt.success).eq(true);
      block_height += 1;

      receipt = await bns.namespaceReady(cases[0].namespace, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');
      block_height += 1;

      var receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        cases[0].salt,
        2560000, {
          sender: cases[0].nameOwner
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include(`${block_height+namespace_preorder_ttl}`);
      block_height += 1;

      receipt = await bns.nameRegister(
        cases[0].namespace,
        "bob",
        cases[0].salt,
        cases[0].zonefile, {
          sender: cases[0].nameOwner
        });
      expect(receipt.result).include('true');
      expect(receipt.success).eq(true);

      // Charlie revoking 'bob.blockstack' on Bob's behalf
      // should fail
      receipt = await bns.nameRevoke(
        cases[0].namespace,
        "bob", {
          sender: charlie
        });
      expect(receipt.error).include('2006');
      expect(receipt.success).eq(false);

      // should resolve as expected
      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "bob", {
          sender: cases[0].nameOwner
        });
      expect(receipt.result).include('0x30303030');
      expect(receipt.success).eq(true);

      // Bob revoking 'bob.blockstack'
      // should succeed
      receipt = await bns.nameRevoke(
        cases[0].namespace,
        "bob", {
          sender: cases[0].nameOwner
        });
      expect(receipt.result).include('true');
      expect(receipt.success).eq(true);

      // should not be able to resolve
      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "bob", {
          sender: cases[0].nameOwner
        });
      expect(receipt.error).include('2014');
      expect(receipt.success).eq(false);

      // Bob trying to update 'bob.blockstack' should fail
      receipt = await bns.nameUpdate(
        cases[0].namespace,
        "bob",
        "4444", {
          sender: bob
        });
      expect(receipt.error).include('2014');
      expect(receipt.success).eq(false);

      // Bob trying to transfer 'bob.blockstack' should fail
      receipt = await bns.nameTransfer(
        cases[0].namespace,
        "bob",
        charlie,
        "4444", {
          sender: bob
        });
      expect(receipt.error).include('2014');
      expect(receipt.success).eq(false);

      // Bob trying to register 'bob.blockstack' should fail
      receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        "salt#2",
        2560000, {
          sender: bob
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u158');

      receipt = await bns.nameRegister(
        cases[0].namespace,
        "bob",
        "salt#2",
        cases[0].zonefile, {
          sender: bob
        });
      expect(receipt.error).include('2004');
      expect(receipt.success).eq(false);

      // Bob trying to renew 'bob.blockstack' should fail
      receipt = await bns.nameRenewal(
        cases[0].namespace,
        "bob",
        2560000,
        bob,
        "4444", {
          sender: bob
        });
      expect(receipt.error).include('2014');
      expect(receipt.success).eq(false);


      // // Alice trying to renew 'alice.blockstack' should succeed
      receipt = await bns.nameRenewal(
        cases[0].namespace,
        "alice",
        2560000,
        alice,
        "6666", {
          sender: alice
        });
      expect(receipt.result).include('true');
      expect(receipt.success).eq(true);
  
      // Bob trying to register 'bob.blockstack', once expired, should succeed
      receipt = await bns.namePreorder(
        cases[0].namespace,
        "bob",
        "salt#3",
        2560000, {
          sender: bob
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u162');

      receipt = await bns.nameRegister(
        cases[0].namespace,
        "bob",
        "salt#3",
        cases[0].zonefile, {
          sender: bob
        });
      expect(receipt.result).include('true');
      expect(receipt.success).eq(true);

      // Charlie revoking 'alice.blockstack' on Alice's behalf (imported name)
      // should fail
      receipt = await bns.nameRevoke(
        cases[0].namespace,
        "alice", {
          sender: charlie
        });
      expect(receipt.error).include('2006');
      expect(receipt.success).eq(false);

      // should resolve as expected
      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "alice", {
          sender: cases[0].nameOwner
        });
      expect(receipt.result).include('0x36363636');
      expect(receipt.success).eq(true);

      // Alice revoking 'alice.blockstack' (imported name)
      // should succeed
      receipt = await bns.nameRevoke(
        cases[0].namespace,
        "alice", {
          sender: alice
        });
      expect(receipt.result).include('true');
      expect(receipt.success).eq(true);

      // should stop resolving
      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "alice", {
          sender: alice
        });
      expect(receipt.error).include('2014');
      expect(receipt.success).eq(false);

      // Alice trying to register 'alice.blockstack' should fail
      receipt = await bns.namePreorder(
        cases[0].namespace,
        "alice",
        "salt#4",
        2560000, {
          sender: alice
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u168');

      receipt = await bns.nameRegister(
        cases[0].namespace,
        "alice",
        "salt#4",
        cases[0].zonefile, {
          sender: alice
        });
      expect(receipt.error).include('2004');
      expect(receipt.success).eq(false);

      // Alice trying to update 'alice.blockstack' should fail
      receipt = await bns.nameUpdate(
        cases[0].namespace,
        "alice",
        "4444", {
          sender: alice
        });
      expect(receipt.error).include('2014');
      expect(receipt.success).eq(false);

      // Alice trying to transfer 'alice.blockstack' should fail
      receipt = await bns.nameTransfer(
        cases[0].namespace,
        "alice",
        charlie,
        "4444", {
          sender: alice
        });
      expect(receipt.error).include('2014');
      expect(receipt.success).eq(false);

      // Alice trying to renew 'alice.blockstack' should fail
      receipt = await bns.nameRenewal(
        cases[0].namespace,
        "alice",
        2560000,
        alice,
        "4444", {
          sender: alice
        });
      expect(receipt.error).include('2014');
      expect(receipt.success).eq(false);

    });
  });
});