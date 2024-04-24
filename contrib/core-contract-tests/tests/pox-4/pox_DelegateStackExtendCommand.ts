import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { assert, expect } from "vitest";
import { Cl, ClarityType, isClarityType } from "@stacks/transactions";
import {
  FIRST_BURNCHAIN_BLOCK_HEIGHT,
  REWARD_CYCLE_LENGTH,
} from "./pox_Commands.ts";

/**
 * The `DelegateStackExtendCommand` allows a pool operator to
 * extend an active stacking lock, issuing a "partial commitment"
 * for the extended-to cycles.
 *
 * This method extends stacker's current lockup for an additional
 * extend-count and partially commits those new cycles to `pox-addr`.
 *
 * Constraints for running this command include:
 * - Stacker must have locked uSTX.
 * - The Operator has to currently be delegated by the Stacker.
 * - The new lock period must be less than or equal to 12.
 */
export class DelegateStackExtendCommand implements PoxCommand {
  readonly operator: Wallet;
  readonly stacker: Wallet;
  readonly extendCount: number;
  readonly currentCycle: number;

  /**
   * Constructs a `DelegateStackExtendCommand` to extend the unlock
   * height as a Pool Operator on behalf of a Stacker.
   *
   * @param operator - Represents the Pool Operator's wallet.
   * @param stacker - Represents the STacker's wallet.
   * @param extendCount - Represents the cycles to be expended.
   * @param currentCycle - Represents the current PoX reward cycle.
   */
  constructor(
    operator: Wallet,
    stacker: Wallet,
    extendCount: number,
    currentCycle: number,
  ) {
    this.operator = operator;
    this.stacker = stacker;
    this.extendCount = extendCount;
    this.currentCycle = currentCycle;
  }

  check(model: Readonly<Stub>): boolean {
    // Constraints for running this command include:
    // - Stacker must have locked uSTX.
    // - The Stacker's uSTX must have been locked by the Operator.
    // - The Operator has to currently be delegated by the Stacker.
    // - The new lock period must be less than or equal to 12.

    const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
    const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;

    const firstRewardCycle =
      this.currentCycle > stackerWallet.firstLockedRewardCycle
        ? this.currentCycle
        : stackerWallet.firstLockedRewardCycle;
    const firstExtendCycle = Math.floor(
      (stackerWallet.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
        REWARD_CYCLE_LENGTH,
    );
    const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
    const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
    const newUnlockHeight =
      REWARD_CYCLE_LENGTH * (firstRewardCycle + totalPeriod - 1) +
      FIRST_BURNCHAIN_BLOCK_HEIGHT;
    const stackedAmount = stackerWallet.amountLocked;

    return (
      stackerWallet.amountLocked > 0 &&
      stackerWallet.hasDelegated === true &&
      stackerWallet.isStacking === true &&
      stackerWallet.delegatedTo === this.operator.stxAddress &&
      stackerWallet.delegatedUntilBurnHt >= newUnlockHeight &&
      stackerWallet.delegatedMaxAmount >= stackedAmount &&
      operatorWallet.poolMembers.includes(this.stacker.stxAddress) &&
      operatorWallet.lockedAddresses.includes(this.stacker.stxAddress) &&
      totalPeriod <= 12
    );
  }

  run(model: Stub, real: Real): void {
    model.trackCommandRun(this.constructor.name);

    const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;

    // Act
    const delegateStackExtend = real.network.callPublicFn(
      "ST000000000000000000002AMW42H.pox-4",
      "delegate-stack-extend",
      [
        // (stacker principal)
        Cl.principal(this.stacker.stxAddress),
        // (pox-addr { version: (buff 1), hashbytes: (buff 32) })
        poxAddressToTuple(stackerWallet.delegatedPoxAddress),
        // (extend-count uint)
        Cl.uint(this.extendCount),
      ],
      this.operator.stxAddress,
    );

    const { result: firstExtendCycle } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "burn-height-to-reward-cycle",
      [Cl.uint(stackerWallet.unlockHeight)],
      this.operator.stxAddress,
    );
    assert(isClarityType(firstExtendCycle, ClarityType.UInt));

    const lastExtendCycle = Number(firstExtendCycle.value) + this.extendCount -
      1;

    const { result: extendedUnlockHeight } = real.network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "reward-cycle-to-burn-height",
      [Cl.uint(lastExtendCycle + 1)],
      this.operator.stxAddress,
    );
    assert(isClarityType(extendedUnlockHeight, ClarityType.UInt));
    const newUnlockHeight = extendedUnlockHeight.value;

    // Assert
    expect(delegateStackExtend.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(this.stacker.stxAddress),
        "unlock-burn-height": Cl.uint(newUnlockHeight),
      }),
    );

    // Get the Stacker's wallet from the model and update it with the new state.
    // Update model so that we know this wallet's unlock height was extended.
    stackerWallet.unlockHeight = Number(newUnlockHeight);

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✓ ${this.operator.label} Ӿ ${this.stacker.label}`,
      "delegate-stack-extend",
      "extend count",
      this.extendCount.toString(),
      "new unlock height",
      stackerWallet.unlockHeight.toString(),
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} delegate-stack-extend extend count ${this.extendCount}`;
  }
}
