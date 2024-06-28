import { poxAddressToTuple } from "@stacks/stacking";
import { logCommand, PoxCommand, Real, Stub, Wallet } from "./pox_CommandModel";
import { currentCycle } from "./pox_Commands";
import { Cl } from "@stacks/transactions";
import { expect } from "vitest";
import { tx } from "@hirosystems/clarinet-sdk";

type CheckFunc = (
  this: StackExtendAuthCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class StackExtendAuthCommand_Err implements PoxCommand {
  readonly wallet: Wallet;
  readonly extendCount: number;
  readonly authId: number;
  readonly currentCycle: number;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `StackExtendAuthCommand_Err` to extend an active stacking lock.
   *
   * This command calls `stack-extend` using an `authorization`.
   *
   * @param wallet - Represents the Stacker's wallet.
   * @param extendCount - Represents the cycles to extend the stack with.
   * @param authId - Unique auth-id for the authorization.
   * @param currentCycle - Represents the current PoX reward cycle.
   * @param checkFunc - A function to check constraints for running this command.
   * @param errorCode - The expected error code when running this command.
   */
  constructor(
    wallet: Wallet,
    extendCount: number,
    authId: number,
    currentCycle: number,
    checkFunc: CheckFunc,
    errorCode: number,
  ) {
    this.wallet = wallet;
    this.extendCount = extendCount;
    this.authId = authId;
    this.currentCycle = currentCycle;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
    const currentRewCycle = currentCycle(real.network);
    const stacker = model.stackers.get(this.wallet.stxAddress)!;

    // Include the authorization and the `stack-extend` transactions in a single
    // block. This way we ensure both the authorization and the stack-extend
    // transactions are called during the same reward cycle, so the authorization
    // currentRewCycle param is relevant for the upcoming stack-extend call.
    const block = real.network.mineBlock([
      tx.callPublicFn(
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
      ),
      tx.callPublicFn(
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
      ),
    ]);

    expect(block[0].result).toBeOk(Cl.bool(true));
    expect(block[1].result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.wallet.label}`,
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
