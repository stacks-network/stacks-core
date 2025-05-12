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
  this: DelegateStxCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class DelegateStxCommand_Err implements PoxCommand {
  readonly wallet: Wallet;
  readonly delegateTo: Wallet;
  readonly untilBurnHt: number;
  readonly amount: bigint;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `DelegateStxCommand_Err` to delegate uSTX for stacking.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param delegateTo - Represents the Delegatee's STX address.
   * @param untilBurnHt - The burn block height until the delegation is valid.
   * @param amount - The maximum amount the `Stacker` delegates the `Delegatee`
   *                 to stack on his behalf.
   * @param checkFunc - A function to check constraints for running this command.
   * @param errorCode - The expected error code when running this command.
   */
  constructor(
    wallet: Wallet,
    delegateTo: Wallet,
    untilBurnHt: number,
    amount: bigint,
    checkFunc: CheckFunc,
    errorCode: number,
  ) {
    this.wallet = wallet;
    this.delegateTo = delegateTo;
    this.untilBurnHt = untilBurnHt;
    this.amount = amount;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
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
    expect(delegateStx.result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.wallet.label}`,
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
