import { describe, it } from "vitest";

import { initSimnet } from "@hirosystems/clarinet-sdk";
import { Real, Stub, StxAddress, Wallet } from "./pox_CommandModel.ts";

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

describe("PoX-4 invariant tests", () => {
  it("statefully does solo stacking with a signature", async () => {
    // SUT stands for "System Under Test".
    const sut: Real = {
      network: await initSimnet(),
    };

    // This is the initial state of the model.
    const model: Stub = {
      stackingMinimum: 0,
      wallets: new Map<StxAddress, Wallet>(),
    };

    const wallets = [
      "7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801",
      "d655b2523bcd65e34889725c73064feb17ceb796831c0e111ba1a552b0f31b3901",
      "3eccc5dac8056590432db6a35d52b9896876a3d5cbdea53b72400bc9c2099fe801",
      "7036b29cb5e235e5fd9b09ae3e8eec4404e44906814d5d01cbca968a60ed4bfb01",
      "b463f0df6c05d2f156393eee73f8016c5372caa0e9e29a901bb7171d90dc4f1401",
    ].map((prvKey) => {
      const pubKey = getPublicKeyFromPrivate(prvKey);
      const devnet = new StacksDevnet();
      const signerPrvKey = createStacksPrivateKey(prvKey);
      const signerPubKey = getPublicKeyFromPrivate(signerPrvKey.data);
      const btcAddress = publicKeyToBtcAddress(pubKey);
      const stxAddress = getAddressFromPrivateKey(
        prvKey,
        TransactionVersion.Testnet
      );

      return {
        prvKey,
        pubKey,
        stxAddress,
        btcAddress,
        signerPrvKey,
        signerPubKey,
        client: new StackingClient(stxAddress, devnet),
        ustxBalance: 100_000_000_000_000,
        isStacking: false,
        hasDelegated: false,
        delegatedTo: "",
        amountLocked: 0,
        unlockHeight: 0,
      };
    });

    // Add the wallets to the model.
    wallets.forEach((wallet) => {
      model.wallets.set(wallet.stxAddress, wallet);
    });

    simnet.setEpoch("3.0");

    fc.assert(
      fc.property(PoxCommands(model.wallets), (cmds) => {
        const initialState = () => ({ model: model, real: sut });
        fc.modelRun(initialState, cmds);
      }),
      {
        numRuns: 1,
        verbose: 2,
      }
    );
  });
});
