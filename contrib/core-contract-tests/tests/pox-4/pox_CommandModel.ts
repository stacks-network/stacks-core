import fc from "fast-check";

import { Simnet } from "@hirosystems/clarinet-sdk";
import {
  ClarityValue,
  cvToValue,
  StacksPrivateKey,
} from "@stacks/transactions";
import { StackingClient } from "@stacks/stacking";

export type StxAddress = string;
export type BtcAddress = string;
export type CommandTag = string;

export class Stub {
  readonly wallets: Map<StxAddress, Wallet>;
  readonly statistics: Map<string, number>;
  stackingMinimum: number;
  nextRewardSetIndex: number;
  lastRefreshedCycle: number;

  constructor(
    wallets: Map<StxAddress, Wallet>,
    statistics: Map<CommandTag, number>,
  ) {
    this.wallets = wallets;
    this.statistics = statistics;
    this.stackingMinimum = 0;
    this.nextRewardSetIndex = 0;
    this.lastRefreshedCycle = 0;
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

  stateRefresh(real: Real) {
    const burnBlockHeightResult = real.network.runSnippet("burn-block-height");
    const burnBlockHeight = cvToValue(burnBlockHeightResult as ClarityValue);
    const lastRefreshedCycle = this.lastRefreshedCycle;
    const currentRewCycle = Math.floor((Number(burnBlockHeight) - 0) / 1050);

    if (lastRefreshedCycle < currentRewCycle) {
      this.nextRewardSetIndex = 0;

      this.wallets.forEach((wallet) => {
        const expiredDelegators = wallet.poolMembers.filter((stackerAddress) =>
          this.wallets.get(stackerAddress)!.delegatedUntilBurnHt + 1 <
            burnBlockHeight
        );
        const expiredStackers = wallet.lockedAddresses.filter(
          (stackerAddress) =>
            this.wallets.get(stackerAddress)!.unlockHeight + 1 <=
              burnBlockHeight,
        );

        expiredDelegators.forEach((expDelegator) => {
          const expDelegatorIndex = wallet.poolMembers.indexOf(expDelegator);
          wallet.poolMembers.splice(expDelegatorIndex, 1);
        });

        expiredStackers.forEach((expStacker) => {
          const expStackerWallet = this.wallets.get(expStacker)!;
          const expStackerIndex = wallet.lockedAddresses.indexOf(expStacker);
          wallet.lockedAddresses.splice(expStackerIndex, 1);
          wallet.amountToCommit -= expStackerWallet.amountLocked;
        });

        if (
          wallet.unlockHeight > 0 && wallet.unlockHeight + 1 <= burnBlockHeight
        ) {
          wallet.isStacking = false;
          wallet.amountUnlocked += wallet.amountLocked;
          wallet.amountLocked = 0;
          wallet.unlockHeight = 0;
          wallet.firstLockedRewardCycle = 0;
        }
        wallet.committedRewCycleIndexes = [];
      });
    }
    this.lastRefreshedCycle = currentRewCycle;
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
  ustxBalance: number;
  isStacking: boolean;
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
  const columnWidth = 23;
  // Pad each column to the same width.
  const prettyPrint = renderItems.map((content) =>
    content ? content.padEnd(columnWidth) : "".padEnd(columnWidth)
  );
  prettyPrint.push("\n");

  process.stdout.write(prettyPrint.join(""));
};
