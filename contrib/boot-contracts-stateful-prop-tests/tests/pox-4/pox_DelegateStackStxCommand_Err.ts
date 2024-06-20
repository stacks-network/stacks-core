import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { expect } from "vitest";
import { Cl, ClarityValue, cvToValue } from "@stacks/transactions";

type CheckFunc = (
  this: DelegateStackStxCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class DelegateStackStxCommand_Err implements PoxCommand {
  readonly operator: Wallet;
  readonly stacker: Wallet;
  readonly period: number;
  readonly amountUstx: bigint;
  readonly unlockBurnHt: number;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `DelegateStackStxCommand` to lock uSTX as a Pool Operator
   * on behalf of a Stacker.
   *
   * @param operator - Represents the Pool Operator's wallet.
   * @param stacker - Represents the Stacker's wallet.
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
    checkFunc: CheckFunc,
    errorCode: number,
  ) {
    this.operator = operator;
    this.stacker = stacker;
    this.period = period;
    this.amountUstx = amountUstx;
    this.unlockBurnHt = unlockBurnHt;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
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

    // Assert
    expect(delegateStackStx.result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.operator.label} Ӿ ${this.stacker.label}`,
      "delegate-stack-stx",
      "lock-amount",
      this.amountUstx.toString(),
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
