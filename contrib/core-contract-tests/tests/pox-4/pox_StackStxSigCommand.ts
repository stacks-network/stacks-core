import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { Pox4SignatureTopic, poxAddressToTuple } from "@stacks/stacking";
import { assert, expect } from "vitest";
import {
  Cl,
  ClarityType,
  ClarityValue,
  cvToValue,
  isClarityType,
} from "@stacks/transactions";
import { currentCycle } from "./pox_Commands.ts";

/**
 * The `StackStxSigCommand` locks STX for stacking within PoX-4. This self-service
 * operation allows the `tx-sender` (the `wallet` in this case) to participate
 * as a Stacker.
 *
 * This command calls stack-stx using a `signature`.
 *
 * Constraints for running this command include:
 * - The Stacker cannot currently be engaged in another stacking operation.
 * - A minimum threshold of uSTX must be met, determined by the
 *   `get-stacking-minimum` function at the time of this call.
 * - The amount of uSTX locked may need to be increased in future reward cycles
 *   if the minimum threshold rises.
 */
export class StackStxSigCommand implements PoxCommand {
  readonly wallet: Wallet;
  readonly authId: number;
  readonly period: number;
  readonly margin: number;

  /**
   * Constructs a `StackStxSigCommand` to lock uSTX for stacking.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param authId - Unique auth-id for the authorization.
   * @param period - Number of reward cycles to lock uSTX.
   * @param margin - Multiplier for minimum required uSTX to stack so that each
   *                 Stacker locks a different amount of uSTX across test runs.
   */
  constructor(
    wallet: Wallet,
    authId: number,
    period: number,
    margin: number,
  ) {
    this.wallet = wallet;
    this.authId = authId;
    this.period = period;
    this.margin = margin;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - A minimum threshold of uSTX must be met, determined by the
    //   `get-stacking-minimum` function at the time of this call.
    // - The Stacker cannot currently be engaged in another stacking operation.
    // - The Stacker cannot currently be delegating STX to a delegatee.

    const stacker = model.stackers.get(this.wallet.stxAddress)!;
    return (
      model.stackingMinimum > 0 && !stacker.isStacking && !stacker.hasDelegated
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);
    const burnBlockHeightCV = real.network.runSnippet("burn-block-height");
    const burnBlockHeight = Number(
      cvToValue(burnBlockHeightCV as ClarityValue),
    );
    const currentRewCycle = currentCycle(real.network);

    // The maximum amount of uSTX that can be used (per tx) with this signer
    // key. For our tests, we will use the minimum amount of uSTX to be stacked
    // in the given reward cycle multiplied by the margin, which is a randomly
    // generated number passed to the constructor of this class.
    const maxAmount = model.stackingMinimum * this.margin;

    const signerSig = this.wallet.stackingClient.signPoxSignature({
      // The signer key being authorized.
      signerPrivateKey: this.wallet.signerPrvKey,
      // The reward cycle for which the authorization is valid.
      // For `stack-stx` and `stack-extend`, this refers to the reward cycle
      // where the transaction is confirmed. For `stack-aggregation-commit`,
      // this refers to the reward cycle argument in that function.
      rewardCycle: currentRewCycle,
      // For `stack-stx`, this refers to `lock-period`. For `stack-extend`,
      // this refers to `extend-count`. For `stack-aggregation-commit`, this is
      // `u1`.
      period: this.period,
      // A string representing the function where this authorization is valid.
      // Either `stack-stx`, `stack-extend`, `stack-increase` or `agg-commit`.
      topic: Pox4SignatureTopic.StackStx,
      // The PoX address that can be used with this signer key.
      poxAddress: this.wallet.btcAddress,
      // The unique auth-id for this authorization.
      authId: this.authId,
      // The maximum amount of uSTX that can be used (per tx) with this signer
      // key.
      maxAmount: maxAmount,
    });

    // The amount of uSTX to be locked in the reward cycle. For this test, we
    // will use the maximum amount of uSTX that can be used (per tx) with this
    // signer key.
    const amountUstx = maxAmount;

    // Act
    const stackStx = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "stack-stx",
      [
        // (amount-ustx uint)
        Cl.uint(amountUstx),
        // (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
        poxAddressToTuple(this.wallet.btcAddress),
        // (start-burn-ht uint)
        Cl.uint(burnBlockHeight),
        // (lock-period uint)
        Cl.uint(this.period),
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

    const { result: rewardCycle } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "burn-height-to-reward-cycle",
      [Cl.uint(burnBlockHeight)],
      this.wallet.stxAddress,
    );
    assert(isClarityType(rewardCycle, ClarityType.UInt));

    const { result: unlockBurnHeight } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "reward-cycle-to-burn-height",
      [Cl.uint(Number(rewardCycle.value) + this.period + 1)],
      this.wallet.stxAddress,
    );
    assert(isClarityType(unlockBurnHeight, ClarityType.UInt));

    // Assert
    expect(stackStx.result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(amountUstx),
        "signer-key": Cl.bufferFromHex(this.wallet.signerPubKey),
        "stacker": Cl.principal(this.wallet.stxAddress),
        "unlock-burn-height": Cl.uint(Number(unlockBurnHeight.value)),
      }),
    );

    // Get the wallet from the model and update it with the new state.
    const wallet = model.stackers.get(this.wallet.stxAddress)!;
    // Update model so that we know this wallet is stacking. This is important
    // in order to prevent the test from stacking multiple times with the same
    // address.
    wallet.isStacking = true;
    wallet.isStackingSolo = true;
    // Update locked, unlocked, and unlock-height fields in the model.
    wallet.amountLocked = amountUstx;
    wallet.unlockHeight = Number(unlockBurnHeight.value);
    wallet.amountUnlocked -= amountUstx;
    wallet.firstLockedRewardCycle = Number(rewardCycle.value) + 1;

    model.nextRewardSetIndex++;

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.wallet.label}`,
      "stack-stx-sig",
      "lock-amount",
      amountUstx.toString(),
      "period",
      this.period.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} stack-stx sig auth-id ${this.authId} and period ${this.period}`;
  }
}
