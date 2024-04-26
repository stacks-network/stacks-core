import { Pox4SignatureTopic, poxAddressToTuple } from "@stacks/stacking";
import { logCommand, PoxCommand, Real, Stub, Wallet } from "./pox_CommandModel";
import { currentCycle } from "./pox_Commands";
import { Cl, cvToJSON } from "@stacks/transactions";
import { expect } from "vitest";
import { tx } from "@hirosystems/clarinet-sdk";

/**
 * The `StackIncreaseAuthCommand` locks up an additional amount
 * of STX from `tx-sender`'s, indicated by `increase-by`.
 *
 * This command calls `stack-increase` using an `authorization`.
 *
 * Constraints for running this command include:
 * - The Stacker must have locked uSTX.
 * - The Stacker must be stacking solo.
 * - The Stacker must not have delegated to a pool.
 * - The increase amount must be less than or equal to the
 *   Stacker's unlocked uSTX amount.
 */

export class StackIncreaseAuthCommand implements PoxCommand {
  readonly wallet: Wallet;
  readonly increaseBy: number;
  readonly authId: number;

  /**
   * Constructs a `StackIncreaseAuthCommand` to increase lock uSTX for stacking.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param increaseBy - Represents the locked amount to be increased by.
   * @param authId - Unique auth-id for the authorization.
   */
  constructor(wallet: Wallet, increaseBy: number, authId: number) {
    this.wallet = wallet;
    this.increaseBy = increaseBy;
    this.authId = authId;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Stacker must have locked uSTX.
    // - The Stacker must be stacking solo.
    // - The Stacker must not have delegated to a pool.
    // - The increse amount must be less or equal to the
    //   Stacker's unlocked uSTX amount.
    const stacker = model.stackers.get(this.wallet.stxAddress)!;

    return (
      model.stackingMinimum > 0 &&
      stacker.isStacking &&
      stacker.isStackingSolo &&
      !stacker.hasDelegated &&
      stacker.amountLocked > 0 &&
      this.increaseBy <= stacker.amountUnlocked &&
      this.increaseBy >= 1
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);

    const currentRewCycle = currentCycle(real.network);
    const stacker = model.stackers.get(this.wallet.stxAddress)!;

    // Get the lock period from the stacking state. This will be used for correctly
    // issuing the authorization.
    const stackingStateCV = real.network.getMapEntry(
      "ST000000000000000000002AMW42H.pox-4",
      "stacking-state",
      Cl.tuple({ stacker: Cl.principal(this.wallet.stxAddress) }),
    );
    const period = cvToJSON(stackingStateCV).value.value["lock-period"].value;

    const maxAmount = stacker.amountLocked + this.increaseBy;

    // Act

    // Include the authorization and the `stack-increase` transactions in a single
    // block. This way we ensure both the authorization and the stack-increase
    // transactions are called during the same reward cycle and avoid the clarity
    // error `ERR_INVALID_REWARD_CYCLE`.
    const block = real.network.mineBlock([
      tx.callPublicFn(
        "ST000000000000000000002AMW42H.pox-4",
        "set-signer-key-authorization",
        [
          // (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
          poxAddressToTuple(this.wallet.btcAddress),
          // (period uint)
          Cl.uint(period),
          // (reward-cycle uint)
          Cl.uint(currentRewCycle),
          // (topic (string-ascii 14))
          Cl.stringAscii(Pox4SignatureTopic.StackIncrease),
          // (signer-key (buff 33))
          Cl.bufferFromHex(this.wallet.signerPubKey),
          // (allowed bool)
          Cl.bool(true),
          // (max-amount uint)
          Cl.uint(maxAmount),
          // (auth-id uint)
          Cl.uint(this.authId),
        ],
        this.wallet.stxAddress,
      ),
      tx.callPublicFn(
        "ST000000000000000000002AMW42H.pox-4",
        "stack-increase",
        [
          // (increase-by uint)
          Cl.uint(this.increaseBy),
          // (signer-sig (optional (buff 65)))
          Cl.none(),
          // (signer-key (buff 33))
          Cl.bufferFromHex(this.wallet.signerPubKey),
          // (max-amount uint)
          Cl.uint(maxAmount),
          // (auth-id uint)
          Cl.uint(this.authId),
        ],
        this.wallet.stxAddress,
      ),
    ]);

    // Assert
    expect(block[0].result).toBeOk(Cl.bool(true));
    expect(block[1].result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(this.wallet.stxAddress),
        "total-locked": Cl.uint(stacker.amountLocked + this.increaseBy),
      }),
    );

    // Get the wallet from the model and update it with the new state.
    const wallet = model.stackers.get(this.wallet.stxAddress)!;
    // Update model so that we know this wallet's locked amount and unlocked
    // amount was extended.
    wallet.amountLocked += this.increaseBy;
    wallet.amountUnlocked -= this.increaseBy;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.wallet.label}`,
      "stack-increase-auth",
      "increase-by",
      this.increaseBy.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} stack-increase auth increase-by ${this.increaseBy}`;
  }
}
