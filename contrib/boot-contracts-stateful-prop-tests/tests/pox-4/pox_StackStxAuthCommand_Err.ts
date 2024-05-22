import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { assert, expect } from "vitest";
import {
  Cl,
  ClarityType,
  ClarityValue,
  cvToValue,
  isClarityType,
} from "@stacks/transactions";
import { currentCycle } from "./pox_Commands.ts";

type CheckFunc = (
  this: StackStxAuthCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class StackStxAuthCommand_Err implements PoxCommand {
  readonly wallet: Wallet;
  readonly authId: number;
  readonly period: number;
  readonly margin: number;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `StackStxAuthCommand_Err` to lock uSTX for stacking.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param authId - Unique auth-id for the authorization.
   * @param period - Number of reward cycles to lock uSTX.
   * @param margin - Multiplier for minimum required uSTX to stack so that each
   *                 Stacker locks a different amount of uSTX across test runs.
   * @param checkFunc - A function to check constraints for running this command.
   * @param errorCode - The expected error code when running this command.
   */
  constructor(
    wallet: Wallet,
    authId: number,
    period: number,
    margin: number,
    checkFunc: CheckFunc,
    errorCode: number,
  ) {
    this.wallet = wallet;
    this.authId = authId;
    this.period = period;
    this.margin = margin;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);
    const currentRewCycle = currentCycle(real.network);

    // The maximum amount of uSTX that can be used (per tx) with this signer
    // key. For our tests, we will use the minimum amount of uSTX to be stacked
    // in the given reward cycle multiplied by the margin, which is a randomly
    // generated number passed to the constructor of this class.
    const maxAmount = model.stackingMinimum * this.margin;

    const { result: setAuthorization } = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "set-signer-key-authorization",
      [
        // (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
        poxAddressToTuple(this.wallet.btcAddress),
        // (period uint)
        Cl.uint(this.period),
        // (reward-cycle uint)
        Cl.uint(currentRewCycle),
        // (topic (string-ascii 14))
        Cl.stringAscii("stack-stx"),
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
    );

    expect(setAuthorization).toBeOk(Cl.bool(true));
    const burnBlockHeightCV = real.network.runSnippet("burn-block-height");
    const burnBlockHeight = Number(
      cvToValue(burnBlockHeightCV as ClarityValue),
    );

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
        Cl.none(),
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
    expect(stackStx.result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.wallet.label}`,
      "stack-stx-auth",
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
    return `${this.wallet.label} stack-stx auth auth-id ${this.authId} and period ${this.period}`;
  }
}