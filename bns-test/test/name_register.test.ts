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

describe("BNS Test Suite - NAME_REGISTER", () => {
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
    renewalRule: 20,
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


  it("should fail if no matching pre-order can be found", async () => {
    await mineBlocks(bns, 20);

    var receipt = await bns.resolvePrincipal(cases[0].nameOwner)
    expect(receipt.result).include('2013');

    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.success).eq(false);
    expect(receipt.error).include('1005');

    receipt = await bns.namespacePreorder(cases[1].namespace, cases[1].salt, cases[1].value, {
      sender: cases[1].namespaceOwner
    });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u167');

    receipt = await bns.namespaceReveal(
      cases[1].namespace,
      cases[1].salt,
      cases[1].priceFunction,
      cases[1].renewalRule,
      cases[1].nameImporter, {
        sender: cases[1].namespaceOwner
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('true');

    receipt = await bns.namePreorder(
      cases[1].namespace,
      "baobab",
      cases[1].salt,
      100, {
        sender: bob
      });
    expect(receipt.result).include('u169');
    expect(receipt.success).eq(true);

    receipt = await bns.nameRegister(
      cases[1].namespace,
      "baobab",
      cases[1].salt,
      cases[1].zonefile, {
        sender: bob
      });
    expect(receipt.error).include('2004');
    expect(receipt.success).eq(false);

    // Given a launched namespace 'blockstack', owned by Alice


    receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
      sender: cases[0].namespaceOwner
    });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u171');

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

    await bns.mineBlocks(1);

    // Revealing the name 'bob.blockstack'
    // should fail if no matching pre-order can be found
    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.success).eq(false);
    expect(receipt.error).include('2001');

    // Given a pre-order of the name 'bub.blockstack', burning 2559999 STX instead of 2560000 STX, Revealing the name
    receipt = await bns.namePreorder(
      cases[0].namespace,
      "bub",
      cases[0].salt,
      2559999, {
        sender: bob
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u176');

    // should fail
    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bub",
      cases[0].salt,
      cases[0].zonefile, {
        sender: bob
      });
    expect(receipt.error).include('2007');
    expect(receipt.success).eq(false);

    // Given an existing pre-order of the name 'Bob.blockstack', initiated by Bob at block #21
    receipt = await bns.namePreorder(
      cases[0].namespace,
      "Bob",
      cases[0].salt,
      2560000, {
        sender: cases[0].nameOwner
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u178');

    // Bob registering the name 'Bob.blockstack' should fail
    receipt = await bns.nameRegister(
      cases[0].namespace,
      "Bob",
      cases[0].salt,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.error).include('2022');
    expect(receipt.success).eq(false);

    // Given an existing pre-order of the name 'bob.blockstack', initiated by Bob at block #21
    receipt = await bns.namePreorder(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      2560000, {
        sender: cases[0].nameOwner
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u180');

    // Bob registering the name 'bob.blockstack'
    // should succeed
    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);

    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('0x30303030');
    expect(receipt.success).eq(true);

    receipt = await bns.resolvePrincipal(cases[0].nameOwner)
    expect(receipt.result).include('0x626f62');

    // should fail registering twice
    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.error).include('2004');
    expect(receipt.success).eq(false);

    // Charlie registering 'bob.blockstack'
    // should fail

    receipt = await bns.namePreorder(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      2560000, {
        sender: charlie
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u184');

    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      cases[0].zonefile, {
        sender: charlie
      });
    expect(receipt.error).include('2004');
    expect(receipt.success).eq(false);

    // // todo(ludo): investigate the case where 'name.namespace' was preordered while being unavailable
    // // and then became available
    // Bob registering a second name 'bobby.blockstack'

    // should fail if 'bob.blockstack' is not expired
    await bns.mineBlocks(1);

    receipt = await bns.namePreorder(
      cases[0].namespace,
      "bobby",
      cases[0].salt,
      160000, {
        sender: cases[0].nameOwner
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u187');

    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bobby",
      cases[0].salt,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.error).include('3001');
    expect(receipt.success).eq(false);


    // should succeed once 'bob.blockstack' is expired
    await mineBlocks(bns, cases[0].renewalRule + 5000);

    receipt = await bns.resolvePrincipal(cases[0].nameOwner)
    expect(receipt.result).include('2008');
    expect(receipt.result).include('0x626f62');

    receipt = await bns.namePreorder(
      cases[0].namespace,
      "bobby",
      cases[0].salt,
      160000, {
        sender: cases[0].nameOwner
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u5199');

    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });

    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bobby",
      cases[0].salt,
      cases[0].zonefile, {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);

    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bobby", {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('0x30303030');
    expect(receipt.success).eq(true);

    // Charlie registering 'bob.blockstack'
    // should succeed once 'bob.blockstack' is expired

    receipt = await bns.namePreorder(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      2560000, {
        sender: charlie
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('u5203');

    receipt = await bns.nameRegister(
      cases[0].namespace,
      "bob",
      cases[0].salt,
      "AAAA", {
        sender: charlie
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);

    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "bob", {
        sender: cases[0].nameOwner
      });
    expect(receipt.result).include('0x41414141');
    expect(receipt.success).eq(true);
  });
});