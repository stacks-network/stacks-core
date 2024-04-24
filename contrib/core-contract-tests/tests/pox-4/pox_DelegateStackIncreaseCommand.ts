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
 * The DelegateStackIncreaseCommand allows a pool operator to
 * increase an active stacking lock, issuing a "partial commitment"
 * for the increased cycles.
 *
 * This method increases stacker's current lockup and partially
 * commits the additional STX to `pox-addr`.
 *
 * Constraints for running this command include:
 * - The Stacker must have locked uSTX.
 * - The Operator has to currently be delegated by the Stacker.
 * - The increase amount must be greater than 0.
 * - Stacker's unlocked uSTX amount must be greater than or equal
 *   to the value of the increase amount.
 * - Stacker's maximum delegated amount must be greater than or equal
 *   to the final locked amount.
 * - The Operator must have locked the Stacker's previously locked funds.
 */
export class DelegateStackIncreaseCommand implements PoxCommand {
  readonly operator: Wallet;
  readonly stacker: Wallet;
  readonly increaseBy: number;

  /**
   * Constructs a DelegateStackIncreaseCommand to increase the uSTX amount
   * previously locked on behalf of a Stacker.
   *
   * @param operator - Represents the Pool Operator's wallet.
   * @param stacker - Represents the Stacker's wallet.
   * @param increaseBy - Represents the locked amount to be increased by.
   */
  constructor(operator: Wallet, stacker: Wallet, increaseBy: number) {
    this.operator = operator;
    this.stacker = stacker;
    this.increaseBy = increaseBy;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Stacker must have locked uSTX.
    // - The Operator has to currently be delegated by the Stacker.
    // - The increase amount must be greater than 0.
    // - Stacker's unlocked uSTX amount must be greater than or equal
    //   to the value of the increase amount.
    // - Stacker's maximum delegated amount must be greater than or equal
    //   to the final locked amount.
    // - The Operator must have locked the Stacker's previously locked funds.

    const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
    const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;

    return (
      stackerWallet.amountLocked > 0 &&
      stackerWallet.hasDelegated === true &&
      stackerWallet.isStacking === true &&
      this.increaseBy > 0 &&
      operatorWallet.poolMembers.includes(this.stacker.stxAddress) &&
      stackerWallet.amountUnlocked >= this.increaseBy &&
      stackerWallet.delegatedMaxAmount >=
        this.increaseBy + stackerWallet.amountLocked &&
      operatorWallet.lockedAddresses.indexOf(this.stacker.stxAddress) > -1
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);

    const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;
    const prevLocked = stackerWallet.amountLocked;
    const newTotalLocked = prevLocked + this.increaseBy;
    // Act
    const delegateStackIncrease = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "delegate-stack-increase",
      [
        // (stacker principal)
        Cl.principal(this.stacker.stxAddress),
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(stackerWallet.delegatedPoxAddress),
        // (increase-by uint)
        Cl.uint(this.increaseBy),
      ],
      this.operator.stxAddress,
    );

    // Assert
    expect(delegateStackIncrease.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(this.stacker.stxAddress),
        "total-locked": Cl.uint(newTotalLocked),
      }),
    );

    // Get the Stacker's wallet from the model and update it with the new state.
    const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
    // Update model so that we know this stacker has increased the stacked amount.
    // Update locked and unlocked fields in the model.
    stackerWallet.amountLocked = newTotalLocked;
    stackerWallet.amountUnlocked = stackerWallet.amountUnlocked -
      this.increaseBy;
    operatorWallet.amountToCommit += this.increaseBy;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.operator.label} Ӿ ${this.stacker.label}`,
      "delegate-stack-increase",
      "increased by",
      this.increaseBy.toString(),
      "previously locked",
      prevLocked.toString(),
      "total locked",
      stackerWallet.amountLocked.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} delegate-stack-increase by ${this.increaseBy}`;
  }
}
