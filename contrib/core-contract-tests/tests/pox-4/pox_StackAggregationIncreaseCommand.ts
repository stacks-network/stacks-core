import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { expect } from "vitest";
import { Cl } from "@stacks/transactions";

/**
 * The `StackAggregationIncreaseCommand` allows an operator to commit
 * partially stacked STX to a PoX address which has already received
 * some STX (more than the `stacking minimum`).
 * This allows a delegator to lock up marginally more STX from new
 * delegates, even if they collectively do not exceed the Stacking
 * minimum, so long as the target PoX address already represents at
 * least as many STX as the `stacking minimum`.
 * This command calls stack-aggregation-increase.
 *
 * Constraints for running this command include:
 * - The Operator must have locked STX on behalf of at least one stacker.
 * - The PoX address must have partial committed STX.
 * - The Reward Cycle Index must be positive.
 */
export class StackAggregationIncreaseCommand implements PoxCommand {
  readonly operator: Wallet;
  readonly currentCycle: number;
  readonly rewardCycleIndex: number;

  /**
   * Constructs a `StackAggregationIncreaseCommand` to commit partially
   * stacked STX to a PoX address which has already received some STX.
   *
   * @param operator - Represents the `Operator`'s wallet.
   * @param currentCycle - The current reward cycle.
   * @param rewardCycleIndex - The cycle index to increase the commit for.
   */
  constructor(
    operator: Wallet,
    currentCycle: number,
    rewardCycleIndex: number,
  ) {
    this.operator = operator;
    this.currentCycle = currentCycle;
    this.rewardCycleIndex = rewardCycleIndex;
  }

  check(_model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Operator must have locked STX on behalf of at least one stacker.
    // - The PoX address must have partial committed STX.
    // - The Reward Cycle Index must be positive.

    return (
      this.operator.lockedAddresses.length > 0 &&
      this.rewardCycleIndex >= 0 &&
      this.operator.amountToCommit > 0
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);

    const committedAmount = this.operator.amountToCommit;

    // Act
    const stackAggregationIncrease = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "stack-aggregation-increase",
      [
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(this.operator.btcAddress),
        // (reward-cycle uint)
        Cl.uint(this.currentCycle + 1),
        // (reward-cycle-index uint))
        Cl.uint(this.rewardCycleIndex),
      ],
      this.operator.stxAddress,
    );

    // Assert
    expect(stackAggregationIncrease.result).toBeOk(Cl.bool(true));

    const operatorWallet = model.wallets.get(this.operator.stxAddress)!;
    operatorWallet.amountToCommit -= committedAmount;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `✓ ${this.operator.label}`,
      "stack-agg-increase",
      "amount committed",
      committedAmount.toString(),
      "cycle index",
      this.rewardCycleIndex.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} stack-aggregation-increase for reward cycle ${
      this.currentCycle + 1
    } index ${this.rewardCycleIndex}`;
  }
}
