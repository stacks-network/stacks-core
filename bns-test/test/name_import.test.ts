import {
  Provider,
  ProviderRegistry,
  NativeClarityBinProvider
} from "@blockstack/clarity";
import {
  getTempFilePath
} from "@blockstack/clarity/lib/utils/fsUtil";
import {
  getDefaultBinaryFilePath
} from "@blockstack/clarity-native-bin";
import {
  expect
} from "chai";
import {
  BNSClient,
  PriceFunction
} from "../src/bns-client";
import {
  mineBlocks
} from "./utils";

describe("BNS Test Suite - NAME_IMPORT", () => {
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
    nameImporter: bob,
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

  describe("Given a launched namespace 'blockstack', owned by Alice, where Bob is nameImporter", () => {

    beforeEach(async () => {
      let receipt = await bns.namespacePreorder(cases[0].namespace, cases[0].salt, cases[0].value, {
        sender: cases[0].namespaceOwner
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('Returned: u146');

      receipt = await bns.namespaceReveal(
        cases[0].namespace,
        cases[0].salt,
        cases[0].priceFunction,
        cases[0].renewalRule,
        cases[0].nameImporter, {
          sender: cases[0].namespaceOwner
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('Returned: true');
      await bns.mineBlocks(1);
    });

    it("Charlie trying to import 'alpha.blockstack' should fail", async () => {
      var receipt = await bns.nameImport(cases[0].namespace, "alpha", charlie, cases[0].zonefile, {
        sender: charlie
      })
      expect(receipt.success).eq(false);
      expect(receipt.error).include('Aborted: 1011');

      // Bob trying to import 'alpha.blockstack' for Alice should succeed
      receipt = await bns.nameImport(cases[0].namespace, "alpha", alice, cases[0].zonefile, {
        sender: bob
      })
      expect(receipt.success).eq(true);
      expect(receipt.result).include('Returned: true');

      // Bob trying to re-import 'alpha.blockstack', but for himself should succeed
      receipt = await bns.nameImport(cases[0].namespace, "alpha", bob, cases[0].zonefile, {
        sender: bob
      })
      expect(receipt.success).eq(true);
      expect(receipt.result).include('Returned: true');

      // Bob trying to import 'dave.blockstack' should succeed
      receipt = await bns.nameImport(cases[0].namespace, "delta", dave, "4444", {
        sender: bob
      })
      expect(receipt.success).eq(true);
      expect(receipt.result).include('Returned: true');

      // Dave trying to update his name should fail
      receipt = await bns.nameUpdate(
        cases[0].namespace,
        "delta",
        "9999", {
          sender: dave
        });
      expect(receipt.error).include('1007');
      expect(receipt.success).eq(false);

      // Bob trying to import a second name for bob 'alpha-2.blockstack' should fail
      receipt = await bns.nameImport(cases[0].namespace, "alpha-2", bob, cases[0].zonefile, {
        sender: bob
      })
      expect(receipt.success).eq(false);
      expect(receipt.error).include('Aborted: 3001');

      // Resolving an imported name should succeed if the namespace is not ready
      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "alpha", {
          sender: cases[0].nameOwner
        });

      expect(receipt.result).include('0x30303030');
      expect(receipt.success).eq(true);

      // Bob trying to import 'beta.blockstack' should fail after the launch of the domain
      receipt = await bns.namespaceReady(cases[0].namespace, {
        sender: bob
      });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');
      await bns.mineBlocks(1);

      receipt = await bns.nameImport(cases[0].namespace, "beta", bob, cases[0].zonefile, {
        sender: bob
      })
      expect(receipt.success).eq(false);
      expect(receipt.error).include('Aborted: 1014');

      // Now that the namespace is ready, Dave should be able to update his name
      receipt = await bns.nameUpdate(
        cases[0].namespace,
        "delta",
        "9999", {
          sender: dave
        });
      expect(receipt.result).include('true');
      expect(receipt.success).eq(true);

      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "delta", {
          sender: dave
        });
      expect(receipt.result).include('0x39393939');
      expect(receipt.success).eq(true);

      receipt = await bns.nameImport(cases[0].namespace, "beta", bob, cases[0].zonefile, {
        sender: bob
      })
      expect(receipt.success).eq(false);
      expect(receipt.error).include('1014');


      // Resolving an imported name should succeed if the namespace is ready
      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "alpha", {
          sender: bob
        });
      expect(receipt.result).include('0x30303030');
      expect(receipt.success).eq(true);


      // Charlie trying to register 'alpha.blockstack' should succeed
      receipt = await bns.namePreorder(
        cases[0].namespace,
        "alpha",
        cases[0].salt,
        160000, {
          sender: charlie
        });
      expect(receipt.success).eq(true);
      expect(receipt.result).include('u163');

      receipt = await bns.nameRegister(
        cases[0].namespace,
        "alpha",
        cases[0].salt,
        cases[0].zonefile, {
          sender: charlie
        });
      expect(receipt.error).include('2004');
      expect(receipt.success).eq(false);

      // Charlie trying to renew 'alpha.blockstack' should fail
      receipt = await bns.nameRenewal(cases[0].namespace, "alpha", 160000, charlie, cases[0].zonefile, {
        sender: charlie
      })
      expect(receipt.success).eq(false);
      expect(receipt.error).include('2006');


      // Bob trying to renew 'alpha.blockstack' should succeed
      receipt = await bns.nameRenewal(cases[0].namespace, "alpha", 160000, charlie, "6666", {
        sender: bob
      })
      expect(receipt.success).eq(true);
      expect(receipt.result).include('true');


      // Should still resolve 10 blocks later
      await bns.mineBlocks(9);

      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "alpha", {
          sender: cases[0].nameOwner
        });
      expect(receipt.result).include('0x36363636');
      expect(receipt.success).eq(true);

      // Should start erroring when entering grace period
      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "alpha", {
          sender: cases[0].nameOwner
        });
      expect(receipt.error).include('2009');
      expect(receipt.success).eq(false);

      // Resolving an imported name should fail after expiration
      await bns.mineBlocks(5100);

      receipt = await bns.getNameZonefile(
        cases[0].namespace,
        "alpha", {
          sender: cases[0].nameOwner
        });

      expect(receipt.error).include('2008');
      expect(receipt.success).eq(false);
    });
  });
});