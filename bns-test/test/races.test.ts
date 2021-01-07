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

describe("BNS Test Suite - RACES", () => {
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

  it("Testing some races", async () => {
    let block_height = 2;
    let namespace_preorder_ttl = 10;
    let name_preorder_ttl = 10;

    // Alice pre-ordering namespace 'blockstack'
    var receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
      sender: cases[0].namespaceOwner
    });
    expect(receipt.success).eq(true);
    expect(receipt.result).include(`${block_height+namespace_preorder_ttl}`);

    // Bob pre-ordering namespace 'blockstack'
    var receipt = await bns.namespacePreorder(cases[0].namespace, "another-salt", cases[0].value, {
      sender: bob
    });
    expect(receipt.success).eq(true);
    expect(receipt.result).include(`${block_height+namespace_preorder_ttl}`);

    // Alice revealing the namespace 'blockstack' should succeed
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

    // Bob revealing the namespace 'blockstack' should fail
    receipt = await bns.namespaceReveal(
      cases[0].namespace,
      "another-salt",
      cases[0].priceFunction,
      cases[0].renewalRule,
      cases[0].nameImporter, {
        sender: bob
      });
    expect(receipt.success).eq(false);
    expect(receipt.error).include('1006'); // ERR_NAMESPACE_ALREADY_EXISTS
    block_height += 1;

    // Alice importing 'alpha.blockstack' for herself should succeed
    receipt = await bns.nameImport(cases[0].namespace, "alpha", alice, "1111", {
      sender: alice
    })
    expect(receipt.success).eq(true);
    expect(receipt.result).include('Returned: true');

    // 'alpha.blockstack' should resolve
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "alpha", {
        sender: dave
      });
    expect(receipt.result).include('0x31313131');
    expect(receipt.success).eq(true);

    // Alice importing 'beta.blockstack' for Charlie should succeed
    receipt = await bns.nameImport(cases[0].namespace, "beta", charlie, "2222", {
      sender: alice
    })
    expect(receipt.success).eq(true);
    expect(receipt.result).include('Returned: true');

    // 'beta.blockstack' should resolve
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "beta", {
        sender: dave
      });
    expect(receipt.result).include('0x32323232');
    expect(receipt.success).eq(true);

    // Alice importing 'delta.blockstack' for Dave should succeed
    receipt = await bns.nameImport(cases[0].namespace, "delta", dave, "5555", {
      sender: alice
    })
    expect(receipt.success).eq(true);
    expect(receipt.result).include('Returned: true');

    // 'delta.blockstack' should resolve
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "delta", {
        sender: dave
      });
    expect(receipt.result).include('0x35353535');
    expect(receipt.success).eq(true);

    // After a NAMESPACE_LAUNCHABILITY_TTL+ blocks, the namespace should expire
    // As a consequence, the imported names should stop resolving
    await bns.mineBlocks(52595);
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "alpha", {
        sender: dave
      });
    expect(receipt.error).include('1010'); // ERR_NAMESPACE_PREORDER_LAUNCHABILITY_EXPIRED
    expect(receipt.success).eq(false);

    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "beta", {
        sender: dave
      });
    expect(receipt.error).include('1010'); // ERR_NAMESPACE_PREORDER_LAUNCHABILITY_EXPIRED
    expect(receipt.success).eq(false);

    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "delta", {
        sender: dave
      });
    expect(receipt.error).include('1010'); // ERR_NAMESPACE_PREORDER_LAUNCHABILITY_EXPIRED
    expect(receipt.success).eq(false);

    // And Alice launching the namespace should fail
    receipt = await bns.namespaceReady(cases[0].namespace, {
      sender: alice
    });
    expect(receipt.success).eq(false);
    expect(receipt.error).include('1010'); // ERR_NAMESPACE_PREORDER_LAUNCHABILITY_EXPIRED

    // Bob pre-ordering and revealing namespace 'blockstack' should succeed
    var receipt = await bns.namespacePreorder(cases[0].namespace, "yet-another-salt", cases[0].value, {
      sender: bob
    });
    expect(receipt.success).eq(true);

    receipt = await bns.namespaceReveal(
      cases[0].namespace,
      "yet-another-salt",
      cases[0].priceFunction,
      cases[0].renewalRule,
      bob, {
        sender: bob
      });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('true');
    block_height += 1;

    // Bob importing 'alpha.blockstack' for himself should succeed
    receipt = await bns.nameImport(cases[0].namespace, "alpha", alice, "8888", {
      sender: bob
    })
    expect(receipt.success).eq(true);
    expect(receipt.result).include('Returned: true');

    // 'alpha.blockstack' should resolve
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "alpha", {
        sender: dave
      });
    expect(receipt.result).include('0x38383838');
    expect(receipt.success).eq(true);

    // Alice importing 'beta.blockstack' for Charlie should succeed
    receipt = await bns.nameImport(cases[0].namespace, "beta", charlie, "9999", {
      sender: bob
    })
    expect(receipt.success).eq(true);
    expect(receipt.result).include('Returned: true');

    // 'beta.blockstack' should resolve
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "beta", {
        sender: dave
      });
    expect(receipt.result).include('0x39393939');
    expect(receipt.success).eq(true);

    // 'delta.blockstack' should still fail
    receipt = await bns.getNameZonefile(
      cases[0].namespace,
      "delta", {
        sender: dave
      });
    expect(receipt.error).include('2008'); // ERR_NAME_EXPIRED
    expect(receipt.success).eq(false);

    // Bob launching the namespace should succeed
    receipt = await bns.namespaceReady(cases[0].namespace, {
      sender: bob
    });
    expect(receipt.success).eq(true);
    expect(receipt.result).include('true');

    // Dave pre-ordering / registering 'dave.blockstack' (initially imported by Alice) should succeed
    receipt = await bns.namePreorder(
      cases[0].namespace,
      "dave",
      cases[0].salt,
      2560000, {
        sender: dave
      });
    expect(receipt.success).eq(true);

    // Bob registering the name 'bob.blockstack'
    // should succeed
    receipt = await bns.nameRegister(
      cases[0].namespace,
      "dave",
      cases[0].salt,
      cases[0].zonefile, {
        sender: dave
      });
    expect(receipt.result).include('true');
    expect(receipt.success).eq(true);

  });
});