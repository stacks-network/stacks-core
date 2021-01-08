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

describe("BNS Test Suite - NAME_RENEWAL", () => {
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
    renewalRule: 0,
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


  it("Given a launched namespace 'id' not requiring renewing names", async () => {
    let block_height = 2;
    let namespace_preorder_ttl = 10;
    let name_preorder_ttl = 10;

    var receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, {
      sender: cases[1].namespaceOwner
    });
    expect(receipt.success).eq(true);
    expect(receipt.result).include(`${block_height+namespace_preorder_ttl}`);
    block_height += 1;

    receipt = await bns.namespaceReveal(
      cases[1].namespace,
      cases[1].salt,
      cases[1].priceFunction,
      cases[1].renewalRule,
      cases[1].nameImporter, {
        sender: cases[1].namespaceOwner
      });
    block_height += 1;
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);

    receipt = await bns.namespaceReady(cases[1].namespace, {
      sender: cases[1].namespaceOwner
    });
    block_height += 1;
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);

    // Charlie should not be able to renew 'charlie.id'
    receipt = await bns.namePreorder(
      cases[1].namespace,
      "charlie",
      cases[1].salt,
      2560000, {
        sender: charlie
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include(`${block_height+name_preorder_ttl}`);
    block_height += 1;

    receipt = await bns.nameRegister(
      cases[1].namespace,
      "charlie",
      cases[1].salt,
      cases[1].zonefile, {
        sender: charlie
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);
    block_height += 1;

    receipt = await bns.nameRenewal(
      cases[1].namespace,
      "charlie",
      2560000,
      null,
      cases[1].zonefile, {
        sender: charlie
      });
    expect(receipt.error).include('2006');
    expect(receipt.success).eq(false);
    block_height += 1;

    // Given a launched namespace 'blockstack' requiring renewing names after 10 blocks
    receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
      sender: cases[0].namespaceOwner
    });
    expect(receipt.success).eq(true);
    expect(receipt.result).include(`${block_height+namespace_preorder_ttl}`);
    block_height += 1;

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

    receipt = await bns.namespaceReady(cases[0].namespace, {
      sender: cases[0].namespaceOwner
    });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('true');
    block_height += 1;

    // Given a registered name 'bob.blockstack', initiated by Bob at block #21
    receipt = await bns.namePreorder(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      2560000, {
        sender: cases[0].nameOwner
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include(`${block_height+name_preorder_ttl}`);
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
    block_height += 1;

    // When Bob is renewing 'bob.blockstack' at block #29
    // should succeed and set the new expiration date to #41
    // await mineBlocks(bns, 8);
    receipt = await bns.nameRenewal(
      cases[0].namespace,
      "bob",
      2560000,
      null,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);
    block_height += 1;

    // should resolve as expected
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('0x30303030');
    expect(receipt.success).eq(true);
    block_height += 1;

    // When Bob is renewing 'bob.blockstack' at block #44 (grace period)
    // should succeed and set the new expiration date to #51
    expect(block_height).eq(15);

    await mineBlocks(bns, 10);

    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });
    expect(receipt.error).include('2009');
    expect(receipt.success).eq(false);
    block_height += 1;

    receipt = await bns.nameRenewal(
      cases[0].namespace,
      "bob",
      2560000,
      null,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);
    block_height += 1;

    // should resolve as expected
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('0x30303030');
    expect(receipt.success).eq(true);
    block_height += 1;

    // When Bob is renewing 'bob.blockstack' at block #56 (expired)
    // should fail renewing
    await mineBlocks(bns, 16 + 5000);

    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });
    expect(receipt.error).include('2008');
    expect(receipt.success).eq(false);
    block_height += 1;

    receipt = await bns.nameRenewal(
      cases[0].namespace,
      "bob",
      2560000,
      null,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.error).include('2008');
    expect(receipt.success).eq(false);
    block_height += 1;

    // Dave should succeed re-registering 'bob.blockstack'
    receipt = await bns.namePreorder(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      2560000, {
        sender: dave
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u5190');
    block_height += 1;

    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      "4444", {
        sender: dave
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);
    block_height += 1;

    // should resolve as expected
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('0x34343434');
    expect(receipt.success).eq(true);
    block_height += 1;

    // Dave should succeed renewing 'bob.blockstack'
    await mineBlocks(bns, 8);

    receipt = await bns.nameRenewal(
      cases[0].namespace,
      "bob",
      2560000,
      bob,
      "1111", {
        sender: dave
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);
    block_height += 1;

    // should resolve as expected
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('0x31313131');
    expect(receipt.success).eq(true);
    block_height += 1;
  });
});