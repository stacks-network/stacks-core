import { PoxCommand, Real, Stub, Wallet } from "./pox_CommandModel.ts";
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
    // Can always check the minimum number of uSTX to be stacked in the given
    // reward cycle.
    return true;
  }

  run(model: Stub, real: Real): void {
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
    console.info(
      `✓ ${this.wallet.label.padStart(8, " ")} ${
        "get-stacking-minimum".padStart(34, " ")
      } ${"pox-4".padStart(12, " ")} ${
        stackingMinimum.value.toString().padStart(13, " ")
      }`,
    );
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} get-stacking-minimum`;
  }
}
