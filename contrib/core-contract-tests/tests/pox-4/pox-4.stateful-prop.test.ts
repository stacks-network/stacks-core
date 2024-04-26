import { it } from "vitest";
import { initSimnet } from "@hirosystems/clarinet-sdk";
import { Real, Stub } from "./pox_CommandModel.ts";

import {
  getPublicKeyFromPrivate,
  publicKeyToBtcAddress,
} from "@stacks/encryption";
import { StacksDevnet } from "@stacks/network";
import {
  createStacksPrivateKey,
  getAddressFromPrivateKey,
  TransactionVersion,
} from "@stacks/transactions";
import { StackingClient } from "@stacks/stacking";

import fc from "fast-check";
import { PoxCommands } from "./pox_Commands.ts";

import fs from "fs";
import path from "path";

it("statefully interacts with PoX-4", async () => {
  // SUT stands for "System Under Test".
  const sut: Real = {
    network: await initSimnet(),
  };

  const wallets = [
    [
      "wallet_1",
      "7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801",
    ],
    [
      "wallet_2",
      "530d9f61984c888536871c6573073bdfc0058896dc1adfe9a6a10dfacadc209101",
    ],
    [
      "wallet_3",
      "d655b2523bcd65e34889725c73064feb17ceb796831c0e111ba1a552b0f31b3901",
    ],
    [
      "wallet_4",
      "f9d7206a47f14d2870c163ebab4bf3e70d18f5d14ce1031f3902fbbc894fe4c701",
    ],
    [
      "wallet_5",
      "3eccc5dac8056590432db6a35d52b9896876a3d5cbdea53b72400bc9c2099fe801",
    ],
    [
      "wallet_6",
      "7036b29cb5e235e5fd9b09ae3e8eec4404e44906814d5d01cbca968a60ed4bfb01",
    ],
    [
      "wallet_7",
      "b463f0df6c05d2f156393eee73f8016c5372caa0e9e29a901bb7171d90dc4f1401",
    ],
    [
      "wallet_8",
      "6a1a754ba863d7bab14adbbc3f8ebb090af9e871ace621d3e5ab634e1422885e01",
    ],
    [
      "wallet_9",
      "de433bdfa14ec43aa1098d5be594c8ffb20a31485ff9de2923b2689471c401b801",
    ],
  ].map((wallet) => {
    const label = wallet[0];
    const prvKey = wallet[1];
    const pubKey = getPublicKeyFromPrivate(prvKey);
    const devnet = new StacksDevnet();
    const initialUstxBalance = 100_000_000_000_000;
    const signerPrvKey = createStacksPrivateKey(prvKey);
    const signerPubKey = getPublicKeyFromPrivate(signerPrvKey.data);
    const btcAddress = publicKeyToBtcAddress(pubKey);
    const stxAddress = getAddressFromPrivateKey(
      prvKey,
      TransactionVersion.Testnet,
    );

    return {
      label,
      stxAddress,
      btcAddress,
      signerPrvKey,
      signerPubKey,
      stackingClient: new StackingClient(stxAddress, devnet),
      ustxBalance: initialUstxBalance,
      isStacking: false,
      hasDelegated: false,
      lockedAddresses: [],
      amountToCommit: 0,
      poolMembers: [],
      delegatedTo: "",
      delegatedMaxAmount: 0,
      delegatedUntilBurnHt: 0,
      delegatedPoxAddress: "",
      amountLocked: 0,
      amountUnlocked: initialUstxBalance,
      unlockHeight: 0,
      firstLockedRewardCycle: 0,
      allowedContractCaller: "",
      callerAllowedBy: [],
      committedRewCycleIndexes: [],
    };
  });

  // Track the number of times each command is run, so we can see if all the
  // commands are run at least once.
  const statistics = fs.readdirSync(path.join(__dirname)).filter((file) =>
    file.startsWith("pox_") && file.endsWith(".ts") &&
    file !== "pox_CommandModel.ts" && file !== "pox_Commands.ts"
  ).map((file) => file.slice(4, -3)); // Remove "pox_" prefix and ".ts" suffix.

  // This is the initial state of the model.
  const model = new Stub(
    new Map(wallets.map((wallet) => [wallet.stxAddress, wallet])),
    new Map(wallets.map((wallet) => [wallet.stxAddress, {
      ustxBalance: 100_000_000_000_000,
      isStacking: false,
      isStackingSolo: false,
      hasDelegated: false,
      lockedAddresses: [],
      amountToCommit: 0,
      poolMembers: [],
      delegatedTo: "",
      delegatedMaxAmount: 0,
      delegatedUntilBurnHt: 0,
      delegatedPoxAddress: "",
      amountLocked: 0,
      amountUnlocked: 100_000_000_000_000,
      unlockHeight: 0,
      firstLockedRewardCycle: 0,
      allowedContractCaller: "",
      callerAllowedBy: [],
      committedRewCycleIndexes: [],
    }])),
    new Map(statistics.map((commandName) => [commandName, 0])),
  );

  simnet.setEpoch("3.0");

  fc.assert(
    fc.property(
      PoxCommands(model.wallets, model.stackers, sut.network),
      (cmds) => {
        const initialState = () => ({ model: model, real: sut });
        fc.modelRun(initialState, cmds);
      },
    ),
    {
      // Defines the number of test iterations to run; default is 100.
      numRuns: 1000,
      // Adjusts the level of detail in test reports. Default is 0 (minimal).
      // At level 2, reports include extensive details, helpful for deep
      // debugging. This includes not just the failing case and its seed, but
      // also a comprehensive log of all executed steps and their outcomes.
      verbose: 2,
    },
  );

  model.reportCommandRuns();
});
