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
    const orderedStatistics = Array.from(this.statistics.entries()).sort(
      ([keyA], [keyB]) => {
        return keyA.localeCompare(keyB);
      },
    );

    this.logAsTree(orderedStatistics);
  }

  private logAsTree(statistics: [string, number][]) {
    const tree: { [key: string]: any } = {};

    statistics.forEach(([commandName, count]) => {
      const split = commandName.split("_");
      let root: string = split[0],
        rest: string = "base";

      if (split.length > 1) {
        rest = split.slice(1).join("_");
      }
      if (!tree[root]) {
        tree[root] = {};
      }
      tree[root][rest] = count;
    });

    const printTree = (node: any, indent: string = "") => {
      const keys = Object.keys(node);
      keys.forEach((key, index) => {
        const isLast = index === keys.length - 1;
        const boxChar = isLast ? "└─ " : "├─ ";
        if (key !== "base") {
          if (typeof node[key] === "object") {
            console.log(`${indent}${boxChar}${key}: ${node[key]["base"]}`);
            printTree(node[key], indent + (isLast ? "    " : "│   "));
          } else {
            console.log(`${indent}${boxChar}${key}: ${node[key]}`);
          }
        }
      });
    };

    printTree(tree);
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
        // If the delegatedUntilBurnHt is undefined, the delegator is considered
        // active for an indefinite period (until a revoke-delegate-stx call).
        const expiredDelegators = wallet.poolMembers.filter(
          (stackerAddress) =>
            this.stackers.get(stackerAddress)!.delegatedUntilBurnHt !==
              undefined &&
            this.stackers.get(stackerAddress)!.delegatedUntilBurnHt as number <
              burnBlockHeight,
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
  delegatedUntilBurnHt: number | undefined;
  delegatedPoxAddress: BtcAddress;
  amountLocked: number;
  amountUnlocked: number;
  unlockHeight: number;
  firstLockedRewardCycle: number;
  allowedContractCallers: StxAddress[];
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

/**
 * Helper function that checks if the minimum uSTX threshold was set in the model.
 * @param model - the model at a given moment in time.
 * @returns boolean.
 */
export const isStackingMinimumCalculated = (model: Readonly<Stub>): boolean =>
  model.stackingMinimum > 0;

/**
 * Helper function that checks if a stacker is currently stacking.
 * @param stacker - the stacker's state at a given moment in time.
 * @returns boolean.
 */
export const isStacking = (stacker: Stacker): boolean =>
  stacker.isStacking;

/**
 * Helper function that checks if a stacker has an active delegation.
 * @param stacker - the stacker's state at a given moment in time.
 * @returns boolean.
 */
export const isDelegating = (stacker: Stacker): boolean =>
  stacker.hasDelegated;

/**
 * Helper function that checks if the stacker is stacking using solo
 * stacking methods.
 * @param stacker - the stacker's state at a given moment in time.
 * @returns boolean.
 */
export const isStackingSolo = (stacker: Stacker): boolean =>
  stacker.isStackingSolo;

/**
 * Helper function that checks if the stacker has locked uSTX.
 * @param stacker - the stacker's state at a given moment in time.
 * @returns boolean.
 */
export const isAmountLockedPositive = (stacker: Stacker): boolean =>
  stacker.amountLocked > 0;

/**
 * Helper function that checks if an operator has locked uSTX on
 * behalf of at least one stacker.
 * @param operator - the operator's state at a given moment in time.
 * @returns boolean.
 */
export const hasLockedStackers = (operator: Stacker): boolean =>
  operator.lockedAddresses.length > 0;

/**
 * Helper function that checks if an operator has uSTX that was not
 * yet committed.
 * @param operator - the operator's state at a given moment in time.
 * @returns boolean.
 *
 * NOTE: ATC is an abbreviation for "amount to commit".
 */
export const isATCPositive = (operator: Stacker): boolean =>
  operator.amountToCommit > 0;

/**
 * Helper function that checks if an operator's not committed uSTX
 * amount is above the minimum stacking threshold.
 * @param operator - the operator's state at a given moment in time.
 * @param model - the model at a given moment in time.
 * @returns boolean.
 *
 * NOTE: ATC is an abbreviation for "amount to commit".
 */ export const isATCAboveThreshold = (
  operator: Stacker,
  model: Readonly<Stub>,
): boolean => operator.amountToCommit >= model.stackingMinimum;

/**
 * Helper function that checks if a uSTX amount fits within a stacker's
 * delegation limit.
 * @param stacker - the stacker's state at a given moment in time.
 * @param amountToCheck - the uSTX amount to check.
 * @returns boolean.
 */
export const isAmountWithinDelegationLimit = (
  stacker: Stacker,
  amountToCheck: bigint | number,
): boolean => stacker.delegatedMaxAmount >= Number(amountToCheck);

/**
 * Helper function that checks if a given unlock burn height is within
 * a stacker's delegation limit.
 * @param stacker - the stacker's state at a given moment in time.
 * @param unlockBurnHt - the verified unlock burn height.
 * @returns boolean.
 *
 * NOTE: UBH is an abbreviation for "unlock burn height".
 */
export const isUBHWithinDelegationLimit = (
  stacker: Stacker,
  unlockBurnHt: number,
): boolean =>
  stacker.delegatedUntilBurnHt === undefined ||
  unlockBurnHt <= stacker.delegatedUntilBurnHt;

/**
 * Helper function that checks if a given amount is within a stacker's
 * unlocked uSTX balance.
 * @param stacker - the stacker's state at a given moment in time.
 * @param amountToCheck - the amount to check.
 * @returns boolean.
 */
export const isAmountWithinBalance = (
  stacker: Stacker,
  amountToCheck: bigint | number,
): boolean => stacker.ustxBalance >= Number(amountToCheck);

/**
 * Helper function that checks if a given amount is above the minimum
 * stacking threshold.
 * @param model - the model at a given moment in time.
 * @param amountToCheck - the amount to check.
 * @returns boolean.
 */
export const isAmountAboveThreshold = (
  model: Readonly<Stub>,
  amountToCheck: bigint | number,
): boolean => Number(amountToCheck) >= model.stackingMinimum;

/**
 * Helper function that checks if an operator has at least one pool
 * participant.
 * @param operator - the operator's state at a given moment in time.
 * @returns boolean.
 */
export const hasPoolMembers = (operator: Stacker): boolean =>
  operator.poolMembers.length > 0;

/**
 * Helper function that checks if a stacker is a pool member of a
 * given operator.
 * @param operator - the operator's state at a given moment in time.
 * @param stacker - the stacker's state at a given moment in time.
 * @returns boolean
 */
export const isStackerInOperatorPool = (
  operator: Stacker,
  stacker: Wallet,
): boolean => operator.poolMembers.includes(stacker.stxAddress);

/**
 * Helper function that checks if a given stacker's funds are locked
 * by a given operator.
 * @param stacker - the stacker's state at a given moment in time.
 * @param operator - the operator's state at a given moment in time.
 * @returns boolean.
 */
export const isStackerLockedByOperator = (
  operator: Stacker,
  stacker: Wallet,
): boolean =>
  operator.lockedAddresses.includes(
    stacker.stxAddress,
  );

/**
 * Helper function that checks if a given stacker's unlock height is
 * within the current reward cycle.
 * @param stacker - the stacker's state at a given moment in time.
 * @param model - the model at a given moment in time.
 * @returns boolean.
 *
 * NOTE: RC is an abbreviation for "reward cycle".
 */
export const isUnlockedWithinCurrentRC = (
  stackerWallet: Stacker,
  model: Readonly<Stub>,
): boolean => (stackerWallet.unlockHeight <=
  model.burnBlockHeight + REWARD_CYCLE_LENGTH);

/**
 * Helper function that checks if the increase amount is within a given
 * stacker's unlocked balance.
 * @param stacker - the stacker's state at a given moment in time.
 * @param increaseBy - the increase amount to check.
 * @returns boolean.
 */
export const isIncreaseByWithinUnlockedBalance = (
  stacker: Stacker,
  increaseBy: number,
): boolean => increaseBy <= stacker.amountUnlocked;

/**
 * Helper function that checks if the increase amount is greater than zero.
 * @param increaseBy - the increase amount to check.
 * @returns boolean.
 */
export const isIncreaseByGTZero = (increaseBy: number): boolean =>
  increaseBy >= 1;

/**
 * Helper function that checks if the increase amount does not exceed the
 * PoX-4 maximum lock period.
 * @param period - the period to check.
 * @returns boolean.
 */
export const isPeriodWithinMax = (period: number) => period <= 12;

/**
 * Helper function that checks if a given stacker is currently delegating
 * to a given operator.
 * @param stacker - the stacker's state at a given moment in time.
 * @param operator - the operator's state at a given moment in time.
 * @returns boolean.
 */
export const isStackerDelegatingToOperator = (
  stacker: Stacker,
  operator: Wallet,
): boolean => stacker.delegatedTo === operator.stxAddress;

/**
 * Helper function that checks if a given increase amount is greater than
 * zero.
 * @param increaseAmount - the increase amount to check
 * @returns boolean.
 */
export const isIncreaseAmountGTZero = (increaseAmount: number): boolean =>
  increaseAmount > 0;

/**
 * Helper function that checks if a given stacker's has issued an allowance
 * to a potential contract caller.
 * @param stacker - the stacker's state at a given moment in time.
 * @param potentialAllowedStacker - the potential contract caller's state.
 * @returns boolean.
 */
export const isAllowedContractCaller = (
  stacker: Stacker,
  potentialAllowedStacker: Wallet,
): boolean =>
  stacker.allowedContractCallers.includes(
    potentialAllowedStacker.stxAddress,
  );

/**
 * Helper function that checks if a given contract caller has been allowed by
 * a given stacker.
 * @param stacker - the stacker's state at a given moment in time.
 * @param caller - the contract caller's state.
 * @returns boolean.
 */
export const isCallerAllowedByStacker = (
  stacker: Wallet,
  caller: Stacker,
): boolean => caller.callerAllowedBy.includes(stacker.stxAddress);

export const isPositive = (value: number): boolean => value >= 0;