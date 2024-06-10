import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { expect } from "vitest";
import { Cl } from "@stacks/transactions";

type CheckFunc = (
  this: RevokeDelegateStxCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class RevokeDelegateStxCommand_Err implements PoxCommand {
  readonly wallet: Wallet;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `RevokeDelegateStxCommand_Err` to revoke a stacking delegation.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param checkFunc - A function to check constraints for running this command.
   * @param errorCode - The expected error code when running this command.
   */
  constructor(wallet: Wallet, checkFunc: CheckFunc, errorCode: number) {
    this.wallet = wallet;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
    // Act
    const revokeDelegateStx = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "revoke-delegate-stx",
      [],
      this.wallet.stxAddress,
    );

    // Assert
    expect(revokeDelegateStx.result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.wallet.label}`,
      "revoke-delegate-stx",
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.stxAddress} revoke-delegate-stx`;
  }
}
