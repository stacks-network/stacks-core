import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { expect } from "vitest";
import { Cl } from "@stacks/transactions";

/**
 * Implements the `PoxCommand` interface to get the info returned from the
 * `stx-account`.
 */
export class GetStxAccountCommand implements PoxCommand {
  readonly wallet: Wallet;

  /**
   * Constructs a new `GetStxAccountCommand`.
   *
   * @param wallet The wallet information, including the STX address used to
   *               query the `stx-account`.
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

    const actual = model.stackers.get(this.wallet.stxAddress)!;
    expect(real.network.runSnippet(`(stx-account '${this.wallet.stxAddress})`))
      .toBeTuple({
        "locked": Cl.uint(actual.amountLocked),
        "unlocked": Cl.uint(actual.amountUnlocked),
        "unlock-height": Cl.uint(actual.unlockHeight),
      });

    expect(actual.amountLocked + actual.amountUnlocked).toBe(
      actual.ustxBalance,
    );

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.wallet.label}`,
      "stx-account",
      "lock-amount",
      actual.amountLocked.toString(),
      "unlocked-amount",
      actual.amountUnlocked.toString(),
      "unlocked-height",
      actual.unlockHeight.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} stx-account`;
  }
}
