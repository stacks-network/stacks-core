import { PoxCommand, Real, Stub, Wallet } from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { expect } from "vitest";
import { boolCV, Cl } from "@stacks/transactions";

/**
 * The `DelegateStxCommand` delegates STX for stacking within PoX-4. This self-service
 * operation allows the `tx-sender` (the `wallet` in this case) to delegate stacking
 * participation to a `delegatee`.
 *
 * Constraints for running this command include:
 * - The Stacker cannot currently be a delegator in another delegation.
 * - The PoX address provided should have a valid version (between 0 and 6 inclusive).
 */
export class DelegateStxCommand implements PoxCommand {
  readonly wallet: Wallet;
  readonly delegateTo: Wallet;
  readonly untilBurnHt: number;
  readonly margin: number;

  /**
   * Constructs a `DelegateStxCommand` to delegate uSTX for stacking.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param delegateTo - Represents the Delegatee's wallet.
   * @param untilBurnHt - The burn block height until the delegation is valid.
   * @param margin - Multiplier for minimum required uSTX to stack so that each
   *                 Stacker locks a different amount of uSTX across test runs.
   */
  constructor(
    wallet: Wallet,
    delegateTo: Wallet,
    untilBurnHt: number,
    margin: number,
  ) {
    this.wallet = wallet;
    this.delegateTo = delegateTo;
    this.untilBurnHt = untilBurnHt;
    this.margin = margin;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Stacker cannot currently be a delegator in another delegation.
    return (
      model.stackingMinimum > 0 &&
      !model.wallets.get(this.wallet.stxAddress)?.hasDelegated
    );
  }

  run(model: Stub, real: Real): void {
    // The amount of uSTX delegated by the Stacker to the Delegatee.
    // For our tests, we will use the minimum amount of uSTX to be stacked
    // in the given reward cycle multiplied by the margin, which is a randomly
    // generated number passed to the constructor of this class. Even if there
    // are no constraints about the delegated amount, it will be checked in the
    // future, when calling delegate-stack-stx.
    const delegatedAmount = model.stackingMinimum * this.margin;

    // The amount of uSTX to be delegated. For this test, we will use the
    // delegated amount calculated before.
    const amountUstx = delegatedAmount;

    // Act
    const delegateStx = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "delegate-stx",
      [
        // (amount-ustx uint)
        Cl.uint(amountUstx),
        // (delegate-to principal)
        Cl.principal(this.delegateTo.stxAddress),
        // (until-burn-ht (optional uint))
        Cl.some(Cl.uint(this.untilBurnHt)),
        // (pox-addr (optional { version: (buff 1), hashbytes: (buff 32) }))
        Cl.some(poxAddressToTuple(this.delegateTo.btcAddress)),
      ],
      this.wallet.stxAddress,
    );

    // Assert
    expect(delegateStx.result).toBeOk(boolCV(true));

    // Get the wallet from the model and update it with the new state.
    const wallet = model.wallets.get(this.wallet.stxAddress)!;
    // Update model so that we know this wallet has delegated. This is important
    // in order to prevent the test from delegating multiple times with the same
    // address.
    wallet.hasDelegated = true;
    wallet.delegatedTo = this.delegateTo.stxAddress;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    console.info(
      `✓ ${this.wallet.label.padStart(8, " ")} ${
        "delegate-stx".padStart(
          34,
          " ",
        )
      } ${"amount".padStart(12, " ")} ${
        amountUstx
          .toString()
          .padStart(13, " ")
      } delegated to ${
        this.delegateTo.label.padStart(
          42,
          " ",
        )
      }`,
    );
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} delegate-stx to ${this.delegateTo.label} until burn ht ${this.untilBurnHt}`;
  }
}
