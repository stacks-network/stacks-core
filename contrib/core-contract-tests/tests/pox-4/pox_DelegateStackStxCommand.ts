import { PoxCommand, Real, Stub, Wallet } from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { assert, expect } from "vitest";
import { Cl, ClarityType, isClarityType } from "@stacks/transactions";

/**
 * The `StackStxCommand` locks STX for stacking within PoX-4. This self-service
 * operation allows the `tx-sender` (the `wallet` in this case) to participate
 * as a Stacker.
 *
 * Constraints for running this command include:
 * - The Stacker cannot currently be engaged in another stacking operation.
 * - A minimum threshold of uSTX must be met, determined by the
 *   `get-stacking-minimum` function at the time of this call.
 * - The amount of uSTX locked may need to be increased in future reward cycles
 *   if the minimum threshold rises.
 */
export class DelegateStackStxCommand implements PoxCommand {
  readonly operator: Wallet;
  readonly stacker: Wallet;
  readonly startBurnHt: number;
  readonly period: number;
  readonly margin: number;

  /**
   * Constructs a `StackStxCommand` to lock uSTX for stacking.
   *
   * @param operator - Represents the Pool Operator's wallet.
   * @param stacker - Represents the STacker's wallet.
   * @param startBurnHt - A burn height inside the current reward cycle.
   * @param period - Number of reward cycles to lock uSTX.
   * @param margin - Multiplier for minimum required uSTX to stack so that each
   *                 Stacker locks a different amount of uSTX across test runs.
   */
  constructor(
    operator: Wallet,
    stacker: Wallet,
    startBurnHt: number,
    period: number,
    margin: number,
  ) {
    this.operator = operator;
    this.stacker = stacker;
    this.startBurnHt = startBurnHt;
    this.period = period;
    this.margin = margin;
  }



  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - A minimum threshold of uSTX must be met, determined by the
    //   `get-stacking-minimum` function at the time of this call.
    // - The Stacker cannot currently be engaged in another stacking 
    //   operation
    // - The Stacker has to currently be delegating to the Caller
    // - The stacked STX amount should be less than or equal to the 
    //   delegated amount
    // - The Caller has to currently be delegated by the Stacker

    const operatorWallet = model.wallets.get(this.operator.stxAddress)!;
    const stackerWallet = model.wallets.get(this.stacker.stxAddress)!;
    return (
      model.stackingMinimum > 0 &&
      !stackerWallet.isStacking &&
      stackerWallet.hasDelegated &&
      stackerWallet.delegatedMaxAmount >= model.stackingMinimum * this.margin &&
      operatorWallet.wasDelegated &&
      operatorWallet.wasDelegatedBy.includes(stackerWallet.stxAddress)
    );
  }

  run(model: Stub, real: Real): void {
    // The amount of uSTX stacked by the Caller on behalf of the Stacker.
    // For our tests, we will use the minimum amount of uSTX to be stacked
    // in the given reward cycle multiplied by the margin, which is a randomly
    // generated number passed to the constructor of this class.
    const amount = model.stackingMinimum * this.margin;

    // The amount of uSTX to be locked in the reward cycle.
    const amountUstx = amount;

    // Act
    const delegateStackStx = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "delegate-stack-stx",
      [
        // (stacker principal)
        Cl.principal(this.stacker.stxAddress),
        // (amount-ustx uint)
        Cl.uint(amountUstx),
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(this.operator.btcAddress),
        // (start-burn-ht uint)
        Cl.uint(this.startBurnHt),
        // (lock-period uint)
        Cl.uint(this.period)
      ],
      this.operator.stxAddress,
    );

    const { result: rewardCycle } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "burn-height-to-reward-cycle",
      [Cl.uint(real.network.blockHeight)],
      this.operator.stxAddress,
    );
    assert(isClarityType(rewardCycle, ClarityType.UInt));

    const { result: unlockBurnHeight } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "reward-cycle-to-burn-height",
      [Cl.uint(Number(rewardCycle.value) + this.period + 1)],
      this.operator.stxAddress,
    );
    assert(isClarityType(unlockBurnHeight, ClarityType.UInt));
    // Assert
    expect(delegateStackStx.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(this.stacker.stxAddress),
        "lock-amount": Cl.uint(amountUstx),
        "unlock-burn-height": Cl.uint(Number(unlockBurnHeight.value)),
      }),
    );

    // Get the wallet from the model and update it with the new state.
    const stackerWallet = model.wallets.get(this.stacker.stxAddress)!;
    // Update model so that we know this wallet is stacking. This is important
    // in order to prevent the test from stacking multiple times with the same
    // address.
    stackerWallet.isStacking = true;
    // Update locked, unlocked, and unlock-height fields in the model.
    stackerWallet.amountLocked = amountUstx;
    stackerWallet.unlockHeight = Number(unlockBurnHeight.value);
    stackerWallet.amountUnlocked -= amountUstx;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    console.info(
      `✓ ${this.operator.label.padStart(8, " ")} ${
        "delegate-stack-stx".padStart(34, " ")
      } ${"lock-amount".padStart(12, " ")} ${
        amountUstx.toString().padStart(13, " ")
      } stacker ${this.stacker.label.padStart(47," ")}`,
    );
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} delegate-stack-stx period ${this.period}`;
  }
}
