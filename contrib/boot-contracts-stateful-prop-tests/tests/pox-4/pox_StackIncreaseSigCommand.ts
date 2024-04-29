import { Pox4SignatureTopic } from "@stacks/stacking";
import { logCommand, PoxCommand, Real, Stub, Wallet } from "./pox_CommandModel";
import {
  Cl,
  ClarityType,
  ClarityValue,
  cvToJSON,
  cvToValue,
  isClarityType,
} from "@stacks/transactions";
import { assert, expect } from "vitest";

/**
 * The `StackIncreaseSigCommand` locks up an additional amount
 * of STX from `tx-sender`'s, indicated by `increase-by`.
 *
 * This command calls `stack-increase` using a `signature`.
 *
 * Constraints for running this command include:
 * - The Stacker must have locked uSTX.
 * - The Stacker must be stacking solo.
 * - The Stacker must not have delegated to a pool.
 * - The increase amount must be less than or equal to the
 *   Stacker's unlocked uSTX amount.
 * - The increase amount must be equal or greater than 1.
 */
export class StackIncreaseSigCommand implements PoxCommand {
  readonly wallet: Wallet;
  readonly increaseBy: number;
  readonly authId: number;

  /**
   * Constructs a `StackIncreaseSigCommand` to lock uSTX for stacking.
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
    // - The increse amount must be less than or equal to the
    //   Stacker's unlocked uSTX amount.
    // - The increase amount must be equal or greater than 1.
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

    const stacker = model.stackers.get(this.wallet.stxAddress)!;

    const maxAmount = stacker.amountLocked + this.increaseBy;

    const burnBlockHeightCV = real.network.runSnippet("burn-block-height");
    const burnBlockHeight = Number(
      cvToValue(burnBlockHeightCV as ClarityValue),
    );

    const { result: rewardCycleNextBlockCV } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "burn-height-to-reward-cycle",
      [Cl.uint(burnBlockHeight + 1)],
      this.wallet.stxAddress,
    );
    assert(isClarityType(rewardCycleNextBlockCV, ClarityType.UInt));

    const rewardCycleNextBlock = cvToValue(rewardCycleNextBlockCV);

    // Get the lock period from the stacking state. This will be used for correctly
    // issuing the authorization.
    const stackingStateCV = real.network.getMapEntry(
      "ST000000000000000000002AMW42H.pox-4",
      "stacking-state",
      Cl.tuple({ stacker: Cl.principal(this.wallet.stxAddress) }),
    );
    const period = cvToJSON(stackingStateCV).value.value["lock-period"].value;

    const signerSig = this.wallet.stackingClient.signPoxSignature({
      // The signer key being authorized.
      signerPrivateKey: this.wallet.signerPrvKey,
      // The reward cycle for which the authorization is valid.
      // For `stack-stx` and `stack-extend`, this refers to the reward cycle
      // where the transaction is confirmed. For `stack-aggregation-commit`,
      // this refers to the reward cycle argument in that function.
      rewardCycle: rewardCycleNextBlock,
      // For `stack-stx`, this refers to `lock-period`. For `stack-extend`,
      // this refers to `extend-count`. For `stack-aggregation-commit`, this is
      // `u1`.
      period: period,
      // A string representing the function where this authorization is valid.
      // Either `stack-stx`, `stack-extend`, `stack-increase` or `agg-commit`.
      topic: Pox4SignatureTopic.StackIncrease,
      // The PoX address that can be used with this signer key.
      poxAddress: this.wallet.btcAddress,
      // The unique auth-id for this authorization.
      authId: this.authId,
      // The maximum amount of uSTX that can be used (per tx) with this signer
      // key.
      maxAmount: maxAmount,
    });

    const stackIncrease = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "stack-increase",
      [
        // (increase-by uint)
        Cl.uint(this.increaseBy),
        // (signer-sig (optional (buff 65)))
        Cl.some(Cl.bufferFromHex(signerSig)),
        // (signer-key (buff 33))
        Cl.bufferFromHex(this.wallet.signerPubKey),
        // (max-amount uint)
        Cl.uint(maxAmount),
        // (auth-id uint)
        Cl.uint(this.authId),
      ],
      this.wallet.stxAddress,
    );

    expect(stackIncrease.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(this.wallet.stxAddress),
        "total-locked": Cl.uint(stacker.amountLocked + this.increaseBy),
      }),
    );

    // Get the wallet from the model and update it with the new state.
    const wallet = model.stackers.get(this.wallet.stxAddress)!;
    // Update model so that we know this wallet's locked amount and unlocked amount was extended.
    wallet.amountLocked += this.increaseBy;
    wallet.amountUnlocked -= this.increaseBy;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.wallet.label}`,
      "stack-increase-sig",
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
    return `${this.wallet.label} stack-increase sig increase-by ${this.increaseBy}`;
  }
}
