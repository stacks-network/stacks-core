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
  this: DisallowContractCallerCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class DisallowContractCallerCommand_Err implements PoxCommand {
  readonly stacker: Wallet;
  readonly callerToDisallow: Wallet;
  readonly checkFunc: CheckFunc;

  /**
   * Constructs a `DisallowContractCallerComand` to revoke authorization
   * for calling stacking methods.
   *
   * @param stacker - Represents the `Stacker`'s wallet.
   * @param callerToDisallow - The `contract-caller` to be revoked.
   * @param checkFunc - A function to check constraints for running this command.
   */
  constructor(stacker: Wallet, callerToDisallow: Wallet, checkFunc: CheckFunc) {
    this.stacker = stacker;
    this.callerToDisallow = callerToDisallow;
    this.checkFunc = checkFunc;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model); // Constraints for running this command include:
  // - The Caller to be disallowed must have been previously allowed
  //   by the Operator.

  run(model: Stub, real: Real): void {
    // Act
    const disallowContractCaller = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "disallow-contract-caller",
      [
        // (caller principal)
        Cl.principal(this.callerToDisallow.stxAddress),
      ],
      this.stacker.stxAddress,
    );

    // Assert
    expect(disallowContractCaller.result).toBeOk(Cl.bool(false));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.stacker.label}`,
      "disallow-contract-caller",
      this.callerToDisallow.label,
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.stacker.label} disallow-contract-caller ${this.callerToDisallow.label}`;
  }
}
