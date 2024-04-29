import { poxAddressToTuple } from "@stacks/stacking";
import { logCommand, PoxCommand, Real, Stub, Wallet } from "./pox_CommandModel";
import {
  currentCycle,
  FIRST_BURNCHAIN_BLOCK_HEIGHT,
  REWARD_CYCLE_LENGTH,
} from "./pox_Commands";
import { Cl, ClarityType, isClarityType } from "@stacks/transactions";
import { assert, expect } from "vitest";

export class StackExtendAuthCommand implements PoxCommand {
  readonly wallet: Wallet;
  readonly extendCount: number;
  readonly authId: number;
  readonly currentCycle: number;

  /**
   * Constructs a `StackExtendAuthCommand` to lock uSTX for stacking.
   *
   * This command calls `stack-extend` using an `authorization`.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param extendCount - Represents the cycles to extend the stack with.
   * @param authId - Unique auth-id for the authorization.
   * @param currentCycle - Represents the current PoX reward cycle.
   *
   * Constraints for running this command include:
   * - The Stacker must have locked uSTX.
   * - The Stacker must be stacking solo.
   * - The Stacker must not have delegated to a pool.
   * - The new lock period must be less than or equal to 12.
   */
  constructor(
    wallet: Wallet,
    extendCount: number,
    authId: number,
    currentCycle: number,
  ) {
    this.wallet = wallet;
    this.extendCount = extendCount;
    this.authId = authId;
    this.currentCycle = currentCycle;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - The Stacker must have locked uSTX.
    // - The Stacker must be stacking solo.
    // - The Stacker must not have delegated to a pool.
    // - The new lock period must be less than or equal to 12.
    const stacker = model.stackers.get(this.wallet.stxAddress)!;

    const firstRewardCycle = stacker.firstLockedRewardCycle < this.currentCycle
      ? this.currentCycle
      : stacker.firstLockedRewardCycle;
    const firstExtendCycle = Math.floor(
      (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
        REWARD_CYCLE_LENGTH,
    );
    const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
    const totalPeriod = lastExtendCycle - firstRewardCycle + 1;

    return (
      model.stackingMinimum > 0 &&
      stacker.isStacking &&
      stacker.isStackingSolo &&
      !stacker.hasDelegated &&
      stacker.amountLocked > 0 &&
      stacker.poolMembers.length === 0 &&
      totalPeriod <= 12
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);
    const currentRewCycle = currentCycle(real.network);

    const stacker = model.stackers.get(this.wallet.stxAddress)!;

    const { result: setAuthorization } = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "set-signer-key-authorization",
      [
        // (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
        poxAddressToTuple(this.wallet.btcAddress),
        // (period uint)
        Cl.uint(this.extendCount),
        // (reward-cycle uint)
        Cl.uint(currentRewCycle),
        // (topic (string-ascii 14))
        Cl.stringAscii("stack-extend"),
        // (signer-key (buff 33))
        Cl.bufferFromHex(this.wallet.signerPubKey),
        // (allowed bool)
        Cl.bool(true),
        // (max-amount uint)
        Cl.uint(stacker.amountLocked),
        // (auth-id uint)
        Cl.uint(this.authId),
      ],
      this.wallet.stxAddress,
    );

    expect(setAuthorization).toBeOk(Cl.bool(true));
    const stackExtend = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "stack-extend",
      [
        // (extend-count uint)
        Cl.uint(this.extendCount),
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(this.wallet.btcAddress),
        // (signer-sig (optional (buff 65)))
        Cl.none(),
        // (signer-key (buff 33))
        Cl.bufferFromHex(this.wallet.signerPubKey),
        // (max-amount uint)
        Cl.uint(stacker.amountLocked),
        // (auth-id uint)
        Cl.uint(this.authId),
      ],
      this.wallet.stxAddress,
    );

    const { result: firstExtendCycle } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "burn-height-to-reward-cycle",
      [Cl.uint(stacker.unlockHeight)],
      this.wallet.stxAddress,
    );
    assert(isClarityType(firstExtendCycle, ClarityType.UInt));

    const lastExtendCycle = Number(firstExtendCycle.value) + this.extendCount -
      1;

    const { result: extendedUnlockHeight } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "reward-cycle-to-burn-height",
      [Cl.uint(lastExtendCycle + 1)],
      this.wallet.stxAddress,
    );
    assert(isClarityType(extendedUnlockHeight, ClarityType.UInt));

    const newUnlockHeight = extendedUnlockHeight.value;

    expect(stackExtend.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(this.wallet.stxAddress),
        "unlock-burn-height": Cl.uint(newUnlockHeight),
      }),
    );

    // Get the wallet from the model and update it with the new state.
    const wallet = model.stackers.get(this.wallet.stxAddress)!;
    // Update model so that we know this wallet's unlock height was extended.
    wallet.unlockHeight = Number(newUnlockHeight);

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.wallet.label}`,
      "stack-extend-auth",
      "extend-count",
      this.extendCount.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} stack-extend auth extend-count ${this.extendCount}`;
  }
}
