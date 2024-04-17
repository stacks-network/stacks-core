import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { expect } from "vitest";
import { boolCV, Cl } from "@stacks/transactions";

/**
 * The `DisallowContractCallerComand` revokes a `contract-caller`'s
 * authorization to call stacking methods.
 *
 * Constraints for running this command include:
 * - The Caller to be disallowed must have been previously
 *   allowed by the Operator.
 */
export class DisallowContractCallerCommand implements PoxCommand {
  readonly stacker: Wallet;
  readonly callerToDisallow: Wallet;

  /**
   * Constructs a `DisallowContractCallerComand` to revoke authorization
   * for calling stacking methods.
   *
   * @param stacker - Represents the `Stacker`'s wallet.
   * @param callerToDisallow - The `contract-caller` to be revoked.
   */
  constructor(stacker: Wallet, callerToDisallow: Wallet) {
    this.stacker = stacker;
    this.callerToDisallow = callerToDisallow;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Caller to be disallowed must have been previously allowed
    //   by the Operator.

    const stacker = model.stackers.get(this.stacker.stxAddress)!;
    const callerToDisallow = model.stackers.get(
      this.callerToDisallow.stxAddress,
    )!;
    return (
      stacker.allowedContractCaller === this.callerToDisallow.stxAddress &&
      callerToDisallow.callerAllowedBy.includes(
          this.stacker.stxAddress,
        ) ===
        true
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);

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
    expect(disallowContractCaller.result).toBeOk(boolCV(true));

    // Get the wallet to be revoked stacking rights from the model and
    // update it with the new state.
    const callerToDisallow = model.stackers.get(
      this.callerToDisallow.stxAddress,
    )!;

    // Update model so that we know that the stacker has revoked stacking
    // allowance.
    const stacker = model.stackers.get(this.stacker.stxAddress)!;
    stacker.allowedContractCaller = "";

    // Remove the operator from the caller to disallow's allowance list.
    const walletIndexAllowedByList = callerToDisallow.callerAllowedBy.indexOf(
      this.stacker.stxAddress,
    );

    expect(walletIndexAllowedByList).toBeGreaterThan(-1);
    callerToDisallow.callerAllowedBy.splice(walletIndexAllowedByList, 1);

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.stacker.label}`,
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
