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

type CheckFunc = (
  this: StackIncreaseSigCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class StackIncreaseSigCommand_Err implements PoxCommand {
  readonly wallet: Wallet;
  readonly increaseBy: number;
  readonly authId: number;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `StackIncreaseSigCommand_Err` to increase the locked uSTX amount.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param increaseBy - Represents the locked amount to be increased by.
   * @param authId - Unique auth-id for the authorization.
   * @param checkFunc - A function to check constraints for running this command.
   * @param errorCode - The expected error code when running this command.
   */
  constructor(
    wallet: Wallet,
    increaseBy: number,
    authId: number,
    checkFunc: CheckFunc,
    errorCode: number,
  ) {
    this.wallet = wallet;
    this.increaseBy = increaseBy;
    this.authId = authId;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
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

    expect(stackIncrease.result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.wallet.label}`,
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
