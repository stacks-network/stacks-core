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
import { currentCycle } from "./pox_Commands.ts";

/**
 * The `StackAggregationCommitAuthCommand` allows an operator to commit
 * partially stacked STX & to allocate a new PoX reward address slot.
 * This allows a stacker to lock fewer STX than the minimal threshold
 * in multiple transactions, so long as:
 *  1. The pox-addr is the same.
 *  2. The "commit" transaction is called _before_ the PoX anchor block.
 *
 * This command calls stack-aggregation-commit using an `authorization`.
 *
 * Constraints for running this command include:
 * - The Operator must have locked STX on behalf of at least one stacker.
 * - The total amount previously locked by the Operator on behalf of the
 *   stackers has to be greater than the uSTX threshold.
 */
export class StackAggregationCommitAuthCommand implements PoxCommand {
  readonly operator: Wallet;
  readonly authId: number;

  /**
   * Constructs a `StackAggregationCommitAuthCommand` to lock uSTX for stacking.
   *
   * @param operator - Represents the `Operator`'s wallet.
   * @param authId - Unique `auth-id` for the authorization.
   */
  constructor(
    operator: Wallet,
    authId: number,
  ) {
    this.operator = operator;
    this.authId = authId;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Operator must have locked STX on behalf of at least one stacker.
    // - The total amount previously locked by the Operator on behalf of the
    //   stackers has to be greater than the uSTX threshold.

    const operator = model.stackers.get(this.operator.stxAddress)!;
    return operator.lockedAddresses.length > 0 &&
      operator.amountToCommit >= model.stackingMinimum;
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);
    const currentRewCycle = currentCycle(real.network);
    const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
    const committedAmount = operatorWallet.amountToCommit;

    const { result: setSignature } = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "set-signer-key-authorization",
      [
        // (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
        poxAddressToTuple(this.operator.btcAddress),
        // (period uint)
        Cl.uint(1),
        // (reward-cycle uint)
        Cl.uint(currentRewCycle + 1),
        // (topic (string-ascii 14))
        Cl.stringAscii("agg-commit"),
        // (signer-key (buff 33))
        Cl.bufferFromHex(this.operator.signerPubKey),
        // (allowed bool)
        Cl.bool(true),
        // (max-amount uint)
        Cl.uint(committedAmount),
        // (auth-id uint)
        Cl.uint(this.authId),
      ],
      this.operator.stxAddress,
    );
    expect(setSignature).toBeOk(Cl.bool(true));

    // Act
    const stackAggregationCommit = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "stack-aggregation-commit",
      [
        // (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
        poxAddressToTuple(this.operator.btcAddress),
        // (reward-cycle uint)
        Cl.uint(currentRewCycle + 1),
        // (signer-sig (optional (buff 65)))
        Cl.none(),
        // (signer-key (buff 33))
        Cl.bufferFromHex(this.operator.signerPubKey),
        // (max-amount uint)
        Cl.uint(committedAmount),
        // (auth-id uint)
        Cl.uint(this.authId),
      ],
      this.operator.stxAddress,
    );

    // Assert
    expect(stackAggregationCommit.result).toBeOk(Cl.bool(true));

    operatorWallet.amountToCommit -= committedAmount;
    operatorWallet.committedRewCycleIndexes.push(model.nextRewardSetIndex);
    model.nextRewardSetIndex++;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.operator.label}`,
      "stack-agg-commit",
      "amount committed",
      committedAmount.toString(),
      "authorization",
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} stack-aggregation-commit auth-id ${this.authId}`;
  }
}
