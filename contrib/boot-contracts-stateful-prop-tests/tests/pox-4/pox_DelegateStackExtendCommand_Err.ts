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

type CheckFunc = (
  this: DelegateStackExtendCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class DelegateStackExtendCommand_Err implements PoxCommand {
  readonly operator: Wallet;
  readonly stacker: Wallet;
  readonly extendCount: number;
  readonly currentCycle: number;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `DelegateStackExtendCommand_Err` to extend the unlock
   * height as a Pool Operator on behalf of a Stacker.
   *
   * @param operator - Represents the Pool Operator's wallet.
   * @param stacker - Represents the Stacker's wallet.
   * @param extendCount - Represents the number of cycles to extend the stack for.
   * @param currentCycle - Represents the current PoX reward cycle.
   * @param checkFunc - A function to check constraints for running this command.
   * @param errorCode - The expected error code when running this command.
   */
  constructor(
    operator: Wallet,
    stacker: Wallet,
    extendCount: number,
    currentCycle: number,
    checkFunc: CheckFunc,
    errorCode: number,
  ) {
    this.operator = operator;
    this.stacker = stacker;
    this.extendCount = extendCount;
    this.currentCycle = currentCycle;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
    const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;

    // Act
    const delegateStackExtend = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "delegate-stack-extend",
      [
        // (stacker principal)
        Cl.principal(this.stacker.stxAddress),
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(this.operator.btcAddress),
        // (extend-count uint)
        Cl.uint(this.extendCount),
      ],
      this.operator.stxAddress,
    );

    expect(delegateStackExtend.result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.operator.label} Ӿ ${this.stacker.label}`,
      "delegate-stack-extend",
      "extend count",
      this.extendCount.toString(),
      "new unlock height",
      stackerWallet.unlockHeight.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} Ӿ ${this.stacker.label} delegate-stack-extend extend count ${this.extendCount}`;
  }
}
