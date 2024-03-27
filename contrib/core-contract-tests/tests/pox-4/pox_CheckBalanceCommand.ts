import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { expect } from "vitest";
import { ClarityValue, cvToValue } from "@stacks/transactions";

/**
 * Implements the `PoxCommand` interface to check a wallet's balance.
 */
export class CheckBalanceCommand implements PoxCommand {
  readonly wallet: Wallet;

  /**
   * Constructs a new `CheckBalanceCommand`.
   *
   * @param wallet The wallet information, including the STX address used to
   *               query the `stx-account`.
   */
  constructor(wallet: Wallet) {
    this.wallet = wallet;
  }

  check(_model: Readonly<Stub>): boolean {
    // Can always check user's balance.
    return true;
  }

  run(model: Stub, real: Real): void {
    const actual = model.wallets.get(this.wallet.stxAddress)!;

    // Get the real balance
    const stxAccount = cvToValue(
      real.network.runSnippet(
        `(stx-account '${actual.stxAddress})`,
      ) as ClarityValue,
    );
    const lockedBalance = parseInt(stxAccount.locked.value);
    const unlockedBalance = parseInt(stxAccount.unlocked.value);
    const realBalance = lockedBalance + unlockedBalance;

    // Check the real balance to equal wallet's ustxBalance
    expect(realBalance).toBe(this.wallet.ustxBalance);

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `✓ ${this.wallet.label}`,
      "check-balance",
      "real-balance",
      realBalance.toString(),
      "wallet-balance",
      this.wallet.ustxBalance.toString(),
    );
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} check-balance`;
  }
}
