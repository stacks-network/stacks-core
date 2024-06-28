import { Pox4SignatureTopic, poxAddressToTuple } from "@stacks/stacking";
import { logCommand, PoxCommand, Real, Stub, Wallet } from "./pox_CommandModel";
import { currentCycle } from "./pox_Commands";
import { Cl, cvToJSON } from "@stacks/transactions";
import { expect } from "vitest";
import { tx } from "@hirosystems/clarinet-sdk";

type CheckFunc = (
  this: StackIncreaseAuthCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class StackIncreaseAuthCommand_Err implements PoxCommand {
  readonly wallet: Wallet;
  readonly increaseBy: number;
  readonly authId: number;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `StackIncreaseAuthCommand_Err` to increase the locked uSTX amount.
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
    expect(block[1].result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.wallet.label}`,
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
