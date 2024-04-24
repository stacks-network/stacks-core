import fc from "fast-check";

import { Simnet } from "@hirosystems/clarinet-sdk";
import {
  ClarityValue,
  cvToValue,
  StacksPrivateKey,
} from "@stacks/transactions";
import { StackingClient } from "@stacks/stacking";
import {
  FIRST_BURNCHAIN_BLOCK_HEIGHT,
  REWARD_CYCLE_LENGTH,
} from "./pox_Commands";

export type StxAddress = string;
export type BtcAddress = string;
export type CommandTag = string;

export class Stub {
  readonly wallets: Map<StxAddress, Wallet>;
  readonly statistics: Map<string, number>;
  readonly stackers: Map<StxAddress, Stacker>;
  stackingMinimum: number;
  nextRewardSetIndex: number;
  lastRefreshedCycle: number;
  burnBlockHeight: number;

  constructor(
    wallets: Map<StxAddress, Wallet>,
    stackers: Map<StxAddress, Stacker>,
    statistics: Map<CommandTag, number>,
  ) {
    this.wallets = wallets;
    this.statistics = statistics;
    this.stackers = stackers;
    this.stackingMinimum = 0;
    this.nextRewardSetIndex = 0;
    this.lastRefreshedCycle = 0;
    this.burnBlockHeight = 0;
  }

  trackCommandRun(commandName: string) {
    const count = this.statistics.get(commandName) || 0;
    this.statistics.set(commandName, count + 1);
  }

  reportCommandRuns() {
    console.log("Command run method execution counts:");
    this.statistics.forEach((count, commandName) => {
      console.log(`${commandName}: ${count}`);
    });
  }

  refreshStateForNextRewardCycle(real: Real) {
    const burnBlockHeightResult = real.network.runSnippet("burn-block-height");
    const burnBlockHeight = Number(
      cvToValue(burnBlockHeightResult as ClarityValue),
    );
    const lastRefreshedCycle = this.lastRefreshedCycle;
    const currentRewCycle = Math.floor(
      (Number(burnBlockHeight) - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
        REWARD_CYCLE_LENGTH,
    );

    // The `this.burnBlockHeight` instance member is used for logging purposes.
    // However, it's not used in the actual implementation of the model and all
    // usages below use the `burnBlockHeight` local variable.
    this.burnBlockHeight = burnBlockHeight;

    if (lastRefreshedCycle < currentRewCycle) {
      this.nextRewardSetIndex = 0;

      this.wallets.forEach((w) => {
        let updatedAmountToCommit = 0;
        const wallet = this.stackers.get(w.stxAddress)!;

        // Get the wallet's ex-delegators by comparing their delegatedUntilBurnHt
        // to the current burn block height (only if the wallet is a delegatee).
        const expiredDelegators = wallet.poolMembers.filter((stackerAddress) =>
          this.stackers.get(stackerAddress)!.delegatedUntilBurnHt <
            burnBlockHeight
        );

        // Get the operator's pool stackers that no longer have partially commited
        // STX for the next reward cycle by comparing their unlock height to
        // the next reward cycle's first block (only if the wallet is an operator).
        const stackersToRemoveAmountToCommit = wallet.lockedAddresses.filter((
          stackerAddress,
        ) =>
          this.stackers.get(stackerAddress)!.unlockHeight <=
            burnBlockHeight + REWARD_CYCLE_LENGTH
        );

        // Get the operator's ex-pool stackers by comparing their unlockHeight to
        // the current burn block height (only if the wallet is an operator).
        const expiredStackers = wallet.lockedAddresses.filter(
          (stackerAddress) =>
            this.stackers.get(stackerAddress)!.unlockHeight <=
              burnBlockHeight,
        );

        // For each remaining pool stacker (if any), increase the operator's
        // amountToCommit (partial-stacked) for the next cycle by the
        // stacker's amountLocked.
        wallet.lockedAddresses.forEach((stacker) => {
          const stackerWallet = this.stackers.get(stacker)!;
          updatedAmountToCommit += stackerWallet?.amountLocked;
        });

        // Update the operator's amountToCommit (partial-stacked).
        wallet.amountToCommit = updatedAmountToCommit;

        // Remove the expired delegators from the delegatee's poolMembers list.
        expiredDelegators.forEach((expDelegator) => {
          const expDelegatorIndex = wallet.poolMembers.indexOf(expDelegator);
          wallet.poolMembers.splice(expDelegatorIndex, 1);
        });

        // Remove the expired stackers from the operator's lockedAddresses list.
        expiredStackers.forEach((expStacker) => {
          const expStackerIndex = wallet.lockedAddresses.indexOf(expStacker);
          wallet.lockedAddresses.splice(expStackerIndex, 1);
        });

        // For each pool stacker that no longer have partially commited STX for
        // the next reward cycle, decrement the operator's amountToCommit
        // (partial-stacked) by the stacker's amountLocked.
        stackersToRemoveAmountToCommit.forEach((expStacker) => {
          const expStackerWallet = this.stackers.get(expStacker)!;
          wallet.amountToCommit -= expStackerWallet.amountLocked;
        });

        // Check the wallet's stack expiry and update the state accordingly.
        if (
          wallet.unlockHeight > 0 && wallet.unlockHeight <= burnBlockHeight
        ) {
          wallet.isStacking = false;
          wallet.isStackingSolo = false;
          wallet.amountUnlocked += wallet.amountLocked;
          wallet.amountLocked = 0;
          wallet.unlockHeight = 0;
          wallet.firstLockedRewardCycle = 0;
        } // If the wallet is solo stacking and its stack won't expire in the
        // next reward cycle, increment the model's nextRewardSetIndex (the
        // next empty reward slot)
        else if (
          wallet.unlockHeight > 0 &&
          wallet.unlockHeight > burnBlockHeight + REWARD_CYCLE_LENGTH &&
          wallet.isStackingSolo
        ) {
          this.nextRewardSetIndex++;
        }
        wallet.committedRewCycleIndexes = [];
      });
      this.lastRefreshedCycle = currentRewCycle;
    }
  }
}

export type Real = {
  network: Simnet;
};

export type Wallet = {
  label: string;
  stxAddress: string;
  btcAddress: string;
  signerPrvKey: StacksPrivateKey;
  signerPubKey: string;
  stackingClient: StackingClient;
};

export type Stacker = {
  ustxBalance: number;
  isStacking: boolean;
  isStackingSolo: boolean;
  hasDelegated: boolean;
  lockedAddresses: StxAddress[];
  amountToCommit: number;
  poolMembers: StxAddress[];
  delegatedTo: StxAddress;
  delegatedMaxAmount: number;
  delegatedUntilBurnHt: number;
  delegatedPoxAddress: BtcAddress;
  amountLocked: number;
  amountUnlocked: number;
  unlockHeight: number;
  firstLockedRewardCycle: number;
  allowedContractCaller: StxAddress;
  callerAllowedBy: StxAddress[];
  committedRewCycleIndexes: number[];
};

export type PoxCommand = fc.Command<Stub, Real>;

export const logCommand = (...items: (string | undefined)[]) => {
  // Ensure we only render up to the first 10 items for brevity.
  const renderItems = items.slice(0, 10);
  const columnWidth = 23; // Standard width for each column after the first two.
  const halfColumns = Math.floor(columnWidth / 2);

  // Pad columns to their widths: half for the first two, full for the rest.
  const prettyPrint = renderItems.map((content, index) =>
    // Check if the index is less than 2 (i.e., first two items).
    content
      ? (index < 2 ? content.padEnd(halfColumns) : content.padEnd(columnWidth))
      : (index < 2 ? "".padEnd(halfColumns) : "".padEnd(columnWidth))
  );
  prettyPrint.push("\n");

  process.stdout.write(prettyPrint.join(""));
};
