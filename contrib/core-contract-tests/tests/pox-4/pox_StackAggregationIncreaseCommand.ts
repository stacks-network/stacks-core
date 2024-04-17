import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { Pox4SignatureTopic, poxAddressToTuple } from "@stacks/stacking";
import { expect } from "vitest";
import { Cl, cvToJSON } from "@stacks/transactions";
import { bufferFromHex } from "@stacks/transactions/dist/cl";
import { currentCycle } from "./pox_Commands.ts";

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
  readonly rewardCycleIndex: number;
  readonly authId: number;

  /**
   * Constructs a `StackAggregationIncreaseCommand` to commit partially
   * stacked STX to a PoX address which has already received some STX.
   *
   * @param operator - Represents the `Operator`'s wallet.
   * @param rewardCycleIndex - The cycle index to increase the commit for.
   * @param authId - Unique `auth-id` for the authorization.
   */
  constructor(
    operator: Wallet,
    rewardCycleIndex: number,
    authId: number,
  ) {
    this.operator = operator;
    this.rewardCycleIndex = rewardCycleIndex;
    this.authId = authId;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Operator must have locked STX on behalf of at least one stacker.
    // - The PoX address must have partial committed STX.
    // - The Reward Cycle Index must be positive.
    const operator = model.stackers.get(this.operator.stxAddress)!;
    return (
      operator.lockedAddresses.length > 0 &&
      this.rewardCycleIndex >= 0 &&
      operator.amountToCommit > 0
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);
    const currentRewCycle = currentCycle(real.network);

    const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
    const committedAmount = operatorWallet.amountToCommit;

    const existingEntryCV = real.network.getMapEntry(
      "ST000000000000000000002AMW42H.pox-4",
      "reward-cycle-pox-address-list",
      Cl.tuple({
        "index": Cl.uint(this.rewardCycleIndex),
        "reward-cycle": Cl.uint(currentRewCycle + 1),
      }),
    );

    const totalStackedBefore =
      cvToJSON(existingEntryCV).value.value["total-ustx"].value;
    const maxAmount = committedAmount + Number(totalStackedBefore);

    const signerSig = this.operator.stackingClient.signPoxSignature({
      // The signer key being authorized.
      signerPrivateKey: this.operator.signerPrvKey,
      // The reward cycle for which the authorization is valid.
      // For stack-stx and stack-extend, this refers to the reward cycle
      // where the transaction is confirmed. For stack-aggregation-commit,
      // this refers to the reward cycle argument in that function.
      rewardCycle: currentRewCycle + 1,
      // For stack-stx, this refers to lock-period. For stack-extend,
      // this refers to extend-count. For stack-aggregation-commit, this is
      // u1.
      period: 1,
      // A string representing the function where this authorization is valid.
      // Either stack-stx, stack-extend, stack-increase, agg-commit or agg-increase.
      topic: Pox4SignatureTopic.AggregateIncrease,
      // The PoX address that can be used with this signer key.
      poxAddress: this.operator.btcAddress,
      // The unique auth-id for this authorization.
      authId: this.authId,
      // The maximum amount of uSTX that can be used (per tx) with this signer
      // key.
      maxAmount: maxAmount,
    });

    // Act
    const stackAggregationIncrease = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "stack-aggregation-increase",
      [
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(this.operator.btcAddress),
        // (reward-cycle uint)
        Cl.uint(currentRewCycle + 1),
        // (reward-cycle-index uint))
        Cl.uint(this.rewardCycleIndex),
        // (signer-sig (optional (buff 65)))
        Cl.some(bufferFromHex(signerSig)),
        // (signer-key (buff 33))
        Cl.bufferFromHex(this.operator.signerPubKey),
        // (max-amount uint)
        Cl.uint(maxAmount),
        // (auth-id uint)
        Cl.uint(this.authId),
      ],
      this.operator.stxAddress,
    );

    // Assert
    expect(stackAggregationIncrease.result).toBeOk(Cl.bool(true));

    operatorWallet.amountToCommit -= committedAmount;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
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
    return `${this.operator.label} stack-aggregation-increase for index ${this.rewardCycleIndex}`;
  }
}
