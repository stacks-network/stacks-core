import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { assert, expect } from "vitest";
import {
  Cl,
  ClarityType,
  ClarityValue,
  cvToValue,
  isClarityType,
} from "@stacks/transactions";
import { currentCycle } from "./pox_Commands.ts";

/**
 * The `DelegateStackStxCommand` locks STX for stacking within PoX-4 on behalf
 * of a delegator. This operation allows the `operator` to stack the `stacker`'s
 * STX.
 *
 * Constraints for running this command include:
 * - A minimum threshold of uSTX must be met, determined by the
 *   `get-stacking-minimum` function at the time of this call.
 * - The Stacker cannot currently be engaged in another stacking operation.
 * - The Stacker has to currently be delegating to the Operator.
 * - The stacked STX amount should be less than or equal to the delegated
 *   amount.
 * - The stacked uSTX amount should be less than or equal to the Stacker's
 *   balance.
 * - The stacked uSTX amount should be greater than or equal to the minimum
 *   threshold of uSTX.
 * - The Operator has to currently be delegated by the Stacker.
 * - The Period has to fit the last delegation burn block height.
 */
export class DelegateStackStxCommand implements PoxCommand {
  readonly operator: Wallet;
  readonly stacker: Wallet;
  readonly period: number;
  readonly amountUstx: bigint;
  readonly unlockBurnHt: number;

  /**
   * Constructs a `DelegateStackStxCommand` to lock uSTX as a Pool Operator
   * on behalf of a Stacker.
   *
   * @param operator - Represents the Pool Operator's wallet.
   * @param stacker - Represents the STacker's wallet.
   * @param period - Number of reward cycles to lock uSTX.
   * @param amountUstx - The uSTX amount stacked by the Operator on behalf
   *                     of the Stacker.
   * @param unlockBurnHt - The burn height at which the uSTX is unlocked.
   */
  constructor(
    operator: Wallet,
    stacker: Wallet,
    period: number,
    amountUstx: bigint,
    unlockBurnHt: number,
  ) {
    this.operator = operator;
    this.stacker = stacker;
    this.period = period;
    this.amountUstx = amountUstx;
    this.unlockBurnHt = unlockBurnHt;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - A minimum threshold of uSTX must be met, determined by the
    //   `get-stacking-minimum` function at the time of this call.
    // - The Stacker cannot currently be engaged in another stacking
    //   operation.
    // - The Stacker has to currently be delegating to the Operator.
    // - The stacked uSTX amount should be less than or equal to the
    //   delegated amount.
    // - The stacked uSTX amount should be less than or equal to the
    //   Stacker's balance.
    // - The stacked uSTX amount should be greater than or equal to the
    //   minimum threshold of uSTX.
    // - The Operator has to currently be delegated by the Stacker.
    // - The Period has to fit the last delegation burn block height.

    const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
    const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;

    return (
      model.stackingMinimum > 0 &&
      !stackerWallet.isStacking &&
      stackerWallet.hasDelegated &&
      stackerWallet.delegatedMaxAmount >= Number(this.amountUstx) &&
      Number(this.amountUstx) <= stackerWallet.ustxBalance &&
      Number(this.amountUstx) >= model.stackingMinimum &&
      operatorWallet.poolMembers.includes(this.stacker.stxAddress) &&
      this.unlockBurnHt <= stackerWallet.delegatedUntilBurnHt
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);
    const burnBlockHeightCV = real.network.runSnippet("burn-block-height");
    const burnBlockHeight = Number(
      cvToValue(burnBlockHeightCV as ClarityValue),
    );

    // Act
    const delegateStackStx = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "delegate-stack-stx",
      [
        // (stacker principal)
        Cl.principal(this.stacker.stxAddress),
        // (amount-ustx uint)
        Cl.uint(this.amountUstx),
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(this.operator.btcAddress),
        // (start-burn-ht uint)
        Cl.uint(burnBlockHeight),
        // (lock-period uint)
        Cl.uint(this.period),
      ],
      this.operator.stxAddress,
    );
    const { result: rewardCycle } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "burn-height-to-reward-cycle",
      [Cl.uint(burnBlockHeight)],
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
        "lock-amount": Cl.uint(this.amountUstx),
        "unlock-burn-height": Cl.uint(Number(unlockBurnHeight.value)),
      }),
    );

    // Get the Stacker's wallet from the model and update it with the new state.
    const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;
    const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
    // Update model so that we know this wallet is stacking. This is important
    // in order to prevent the test from stacking multiple times with the same
    // address.
    stackerWallet.isStacking = true;
    // Update locked, unlocked, and unlock-height fields in the model.
    stackerWallet.amountLocked = Number(this.amountUstx);
    stackerWallet.unlockHeight = Number(unlockBurnHeight.value);
    stackerWallet.amountUnlocked -= Number(this.amountUstx);
    stackerWallet.firstLockedRewardCycle = currentCycle(real.network) + 1;
    // Add stacker to the operators lock list. This will help knowing that
    // the stacker's funds are locked when calling delegate-stack-extend
    // and delegate-stack-increase.
    operatorWallet.lockedAddresses.push(this.stacker.stxAddress);
    operatorWallet.amountToCommit += Number(this.amountUstx);

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.operator.label} Ӿ ${this.stacker.label}`,
      "delegate-stack-stx",
      "lock-amount",
      this.amountUstx.toString(),
      "until",
      stackerWallet.unlockHeight.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} delegate-stack-stx stacker ${this.stacker.label} period ${this.period}`;
  }
}
