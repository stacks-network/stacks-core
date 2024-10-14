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
  this: DelegateStackIncreaseCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class DelegateStackIncreaseCommand_Err implements PoxCommand {
  readonly operator: Wallet;
  readonly stacker: Wallet;
  readonly increaseBy: number;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `DelegateStackIncreaseCommand_Err` to increase the uSTX amount
   * previously locked on behalf of a Stacker.
   *
   * @param operator - Represents the Pool Operator's wallet.
   * @param stacker - Represents the Stacker's wallet.
   * @param increaseBy - Represents the locked amount to be increased by.
   * @param checkFunc - A function to check constraints for running this command.
   * @param errorCode - The expected error code when running this command.
   */
  constructor(
    operator: Wallet,
    stacker: Wallet,
    increaseBy: number,
    checkFunc: CheckFunc,
    errorCode: number,
  ) {
    this.operator = operator;
    this.stacker = stacker;
    this.increaseBy = increaseBy;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
    const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;
    const prevLocked = stackerWallet.amountLocked;
    // Act
    const delegateStackIncrease = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "delegate-stack-increase",
      [
        // (stacker principal)
        Cl.principal(this.stacker.stxAddress),
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(this.operator.btcAddress),
        // (increase-by uint)
        Cl.uint(this.increaseBy),
      ],
      this.operator.stxAddress,
    );

    // Assert
    expect(delegateStackIncrease.result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.operator.label} Ӿ ${this.stacker.label}`,
      "delegate-stack-increase",
      "increased by",
      this.increaseBy.toString(),
      "previously locked",
      prevLocked.toString(),
      "total locked",
      stackerWallet.amountLocked.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} delegate-stack-increase by ${this.increaseBy}`;
  }
}
