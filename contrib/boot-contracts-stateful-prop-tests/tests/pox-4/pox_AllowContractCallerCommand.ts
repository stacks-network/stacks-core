import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { expect } from "vitest";
import {
  boolCV,
  Cl,
  ClarityType,
  OptionalCV,
  UIntCV,
} from "@stacks/transactions";

/**
 * The `AllowContractCallerCommand` authorizes a `contract-caller` to call
 * stacking methods. Normally, stacking methods can only be invoked by direct
 * transactions (i.e., the tx-sender issues a direct contract-call to the
 * stacking methods). By issuing an allowance, the tx-sender may call stacking
 * methods through the allowed contract.
 *
 * There are no constraints for running this command.
 */
export class AllowContractCallerCommand implements PoxCommand {
  readonly wallet: Wallet;
  readonly allowanceTo: Wallet;
  readonly allowUntilBurnHt: OptionalCV<UIntCV>;

  /**
   * Constructs an `AllowContractCallerCommand` that authorizes a
   * `contract-caller` to call stacking methods.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param allowanceTo - Represents the authorized `contract-caller` (i.e., a
   *                      stacking pool).
   * @param allowUntilBurnHt - The burn block height until which the
   *                           authorization is valid.
   */
  constructor(
    wallet: Wallet,
    allowanceTo: Wallet,
    allowUntilBurnHt: OptionalCV<UIntCV>,
  ) {
    this.wallet = wallet;
    this.allowanceTo = allowanceTo;
    this.allowUntilBurnHt = allowUntilBurnHt;
  }

  check(): boolean {
    // There are no constraints for running this command.
    return true;
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);

    // Act
    const allowContractCaller = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "allow-contract-caller",
      [
        // (caller principal)
        Cl.principal(this.allowanceTo.stxAddress),
        // (until-burn-ht (optional uint))
        this.allowUntilBurnHt,
      ],
      this.wallet.stxAddress,
    );

    // Assert
    expect(allowContractCaller.result).toBeOk(boolCV(true));

    // Get the wallets involved from the model and update it with the new state.
    const wallet = model.stackers.get(this.wallet.stxAddress)!;
    const callerAllowedBefore = wallet.allowedContractCaller;

    const callerAllowedBeforeState = model.stackers.get(callerAllowedBefore) ||
      null;

    if (callerAllowedBeforeState) {
      // Remove the allower from the ex-allowed caller's allowance list.

      const walletIndexInsideAllowedByList = callerAllowedBeforeState
        .callerAllowedBy.indexOf(
          this.wallet.stxAddress,
        );

      expect(walletIndexInsideAllowedByList).toBeGreaterThan(-1);

      callerAllowedBeforeState.callerAllowedBy.splice(
        walletIndexInsideAllowedByList,
        1,
      );
    }

    const callerToAllow = model.stackers.get(this.allowanceTo.stxAddress)!;
    // Update model so that we know this wallet has authorized a contract-caller.

    wallet.allowedContractCaller = this.allowanceTo.stxAddress;
    callerToAllow.callerAllowedBy.push(this.wallet.stxAddress);

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.wallet.label}`,
      "allow-contract-caller",
      this.allowanceTo.label,
      "until",
      optionalCVToString(this.allowUntilBurnHt),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.stxAddress} allow-contract-caller ${this.allowanceTo.stxAddress} until burn ht ${
      optionalCVToString(this.allowUntilBurnHt)
    }`;
  }
}

const optionalCVToString = (optional: OptionalCV): string =>
  optional.type === ClarityType.OptionalSome
    ? (optional.value as UIntCV).value.toString()
    : "none";
