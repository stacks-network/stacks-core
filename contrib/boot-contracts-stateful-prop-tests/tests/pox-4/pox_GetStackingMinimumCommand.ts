import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { assert } from "vitest";
import { ClarityType, isClarityType } from "@stacks/transactions";

/**
 * Implements the `PoxCommand` interface to get the minimum stacking amount
 * required for a given reward cycle.
 */
export class GetStackingMinimumCommand implements PoxCommand {
  readonly wallet: Wallet;

  /**
   * Constructs a new `GetStackingMinimumCommand`.
   *
   * @param wallet The wallet information, including the STX address used to
   *               query the stacking minimum requirement.
   */
  constructor(wallet: Wallet) {
    this.wallet = wallet;
  }

  check(_model: Readonly<Stub>): boolean {
    // There are no constraints for running this command.
    return true;
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);

    // Act
    const { result: stackingMinimum } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "get-stacking-minimum",
      [],
      this.wallet.stxAddress,
    );
    assert(isClarityType(stackingMinimum, ClarityType.UInt));

    // Update the model with the new stacking minimum. This is important for
    // the `check` method of the `StackStxCommand` class to work correctly, as
    // we as other tests that may depend on the stacking minimum.
    model.stackingMinimum = Number(stackingMinimum.value);

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.wallet.label}`,
      "get-stacking-minimum",
      "pox-4",
      stackingMinimum.value.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} get-stacking-minimum`;
  }
}
