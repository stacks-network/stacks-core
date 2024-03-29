import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { expect } from "vitest";
import { Cl, someCV, tupleCV } from "@stacks/transactions";

/**
 * The `RevokeDelegateStxCommand` revokes the delegation for stacking within PoX-4.
 *
 * Constraints for running this command include:
 * - The `Stacker` has to currently be delegating.
 */
export class RevokeDelegateStxCommand implements PoxCommand {
  readonly wallet: Wallet;

  /**
   * Constructs a RevokeDelegateStxCommand to revoke delegate uSTX for stacking.
   *
   * @param wallet - Represents the Stacker's wallet.
   */
  constructor(wallet: Wallet) {
    this.wallet = wallet;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Stacker has to currently be delegating.
    return (
      model.stackingMinimum > 0 &&
      model.wallets.get(this.wallet.stxAddress)!.hasDelegated === true
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);
    // Get the Operator's wallet
    const operatorWallet = model.wallets.get(this.wallet.delegatedTo)!;

    // Act
    const revokeDelegateStx = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "revoke-delegate-stx",
      [],
      this.wallet.stxAddress,
    );

    // Assert
    expect(revokeDelegateStx.result).toBeOk(
      someCV(
        tupleCV({
          "amount-ustx": Cl.uint(this.wallet.delegatedMaxAmount),
          "delegated-to": Cl.principal(
            operatorWallet.stxAddress || "",
          ),
          "pox-addr": Cl.some(
            poxAddressToTuple(this.wallet.delegatedPoxAddress || ""),
          ),
          "until-burn-ht": Cl.some(Cl.uint(this.wallet.delegatedUntilBurnHt)),
        }),
      ),
    );

    // Get the Stacker's wallet from the model and update the two wallets involved with the new state.
    const wallet = model.wallets.get(this.wallet.stxAddress)!;
    // Update model so that we know this wallet is not delegating anymore.
    // This is important in order to prevent the test from revoking the delegation
    // multiple times with the same address.
    wallet.hasDelegated = false;
    wallet.delegatedTo = "";
    wallet.delegatedUntilBurnHt = 0;
    wallet.delegatedMaxAmount = 0;

    // Remove the Stacker from the Pool Operator's pool members list
    const walletIndexInDelegatorsList = operatorWallet.poolMembers.indexOf(
      wallet.stxAddress,
    );
    expect(walletIndexInDelegatorsList).toBeGreaterThan(-1);
    operatorWallet.poolMembers.splice(walletIndexInDelegatorsList, 1);

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(`✓ ${this.wallet.label}`, "revoke-delegate-stx");
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.stxAddress} revoke-delegate-stx`;
  }
}
