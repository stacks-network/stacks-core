import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { expect } from "vitest";
import { boolCV, Cl } from "@stacks/transactions";

/**
 * The `DelegateStxCommand` delegates STX for stacking within PoX-4. This
 * operation allows the `tx-sender` (the `wallet` in this case) to delegate
 * stacking participation to a `delegatee`.
 *
 * Constraints for running this command include:
 * - The Stacker cannot currently be a delegator in another delegation.
 * - The PoX address provided should have a valid version (between 0 and 6
 *   inclusive).
 */
export class DelegateStxCommand implements PoxCommand {
  readonly wallet: Wallet;
  readonly delegateTo: Wallet;
  readonly untilBurnHt: number;
  readonly amount: bigint;

  /**
   * Constructs a `DelegateStxCommand` to delegate uSTX for stacking.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param delegateTo - Represents the Delegatee's STX address.
   * @param untilBurnHt - The burn block height until the delegation is valid.
   * @param amount - The maximum amount the `Stacker` delegates the `Delegatee`
   *                 to stack on his behalf.
   */
  constructor(
    wallet: Wallet,
    delegateTo: Wallet,
    untilBurnHt: number,
    amount: bigint,
  ) {
    this.wallet = wallet;
    this.delegateTo = delegateTo;
    this.untilBurnHt = untilBurnHt;
    this.amount = amount;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Stacker cannot currently be a delegator in another delegation.

    return (
      model.stackingMinimum > 0 &&
      !model.stackers.get(this.wallet.stxAddress)?.hasDelegated
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);

    // The amount of uSTX delegated by the Stacker to the Delegatee.
    // Even if there are no constraints about the delegated amount,
    // it will be checked in the future, when calling delegate-stack-stx.
    const amountUstx = Number(this.amount);

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
    const wallet = model.stackers.get(this.wallet.stxAddress)!;
    const delegatedWallet = model.stackers.get(this.delegateTo.stxAddress)!;
    // Update model so that we know this wallet has delegated. This is important
    // in order to prevent the test from delegating multiple times with the same
    // address.
    wallet.hasDelegated = true;
    wallet.delegatedTo = this.delegateTo.stxAddress;
    wallet.delegatedMaxAmount = amountUstx;
    wallet.delegatedUntilBurnHt = this.untilBurnHt;
    wallet.delegatedPoxAddress = this.delegateTo.btcAddress;

    delegatedWallet.poolMembers.push(this.wallet.stxAddress);
    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.wallet.label}`,
      "delegate-stx",
      "amount",
      amountUstx.toString(),
      "delegated to",
      this.delegateTo.label,
      "until",
      this.untilBurnHt.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} delegate-stx to ${this.delegateTo.label} until burn ht ${this.untilBurnHt}`;
  }
}
