import {
  logCommand,
  PoxCommand,
  Real,
  Stub,
  Wallet,
} from "./pox_CommandModel.ts";
import { poxAddressToTuple } from "@stacks/stacking";
import { expect } from "vitest";
import { Cl } from "@stacks/transactions";
import { currentCycle } from "./pox_Commands.ts";
import { tx } from "@hirosystems/clarinet-sdk";

type CheckFunc = (
  this: StackAggregationCommitAuthCommand_Err,
  model: Readonly<Stub>,
) => boolean;

export class StackAggregationCommitAuthCommand_Err implements PoxCommand {
  readonly operator: Wallet;
  readonly authId: number;
  readonly checkFunc: CheckFunc;
  readonly errorCode: number;

  /**
   * Constructs a `StackAggregationCommitAuthCommand_Err` to commit partially 
   * locked uSTX.
   *
   * @param operator - Represents the `Operator`'s wallet.
   * @param authId - Unique `auth-id` for the authorization.
   * @param checkFunc - A function to check constraints for running this command.
   * @param errorCode - The expected error code when running this command.
   */
  constructor(
    operator: Wallet,
    authId: number,
    checkFunc: CheckFunc,
    errorCode: number,
  ) {
    this.operator = operator;
    this.authId = authId;
    this.checkFunc = checkFunc;
    this.errorCode = errorCode;
  }

  check = (model: Readonly<Stub>): boolean => this.checkFunc.call(this, model);

  run(model: Stub, real: Real): void {
    const currentRewCycle = currentCycle(real.network);
    const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
    const committedAmount = operatorWallet.amountToCommit;

    // Include the authorization and the `stack-aggregation-commit` transactions
    // in a single block. This way we ensure both the authorization and the
    // stack-aggregation-commit transactions are called during the same reward
    // cycle, so the authorization currentRewCycle param is relevant for the
    // upcoming stack-aggregation-commit call.
    const block = real.network.mineBlock([
      tx.callPublicFn(
        "ST000000000000000000002AMW42H.pox-4",
        "set-signer-key-authorization",
        [
          // (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
          poxAddressToTuple(this.operator.btcAddress),
          // (period uint)
          Cl.uint(1),
          // (reward-cycle uint)
          Cl.uint(currentRewCycle + 1),
          // (topic (string-ascii 14))
          Cl.stringAscii("agg-commit"),
          // (signer-key (buff 33))
          Cl.bufferFromHex(this.operator.signerPubKey),
          // (allowed bool)
          Cl.bool(true),
          // (max-amount uint)
          Cl.uint(committedAmount),
          // (auth-id uint)
          Cl.uint(this.authId),
        ],
        this.operator.stxAddress,
      ),
      tx.callPublicFn(
        "ST000000000000000000002AMW42H.pox-4",
        "stack-aggregation-commit",
        [
          // (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
          poxAddressToTuple(this.operator.btcAddress),
          // (reward-cycle uint)
          Cl.uint(currentRewCycle + 1),
          // (signer-sig (optional (buff 65)))
          Cl.none(),
          // (signer-key (buff 33))
          Cl.bufferFromHex(this.operator.signerPubKey),
          // (max-amount uint)
          Cl.uint(committedAmount),
          // (auth-id uint)
          Cl.uint(this.authId),
        ],
        this.operator.stxAddress,
      ),
    ]);

    // Assert
    expect(block[0].result).toBeOk(Cl.bool(true));
    expect(block[1].result).toBeErr(Cl.int(this.errorCode));

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(
      `₿ ${model.burnBlockHeight}`,
      `✗ ${this.operator.label}`,
      "stack-agg-commit",
      "amount committed",
      committedAmount.toString(),
      "authorization",
    );

    // Refresh the model's state if the network gets to the next reward cycle.
    model.refreshStateForNextRewardCycle(real);
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.operator.label} stack-aggregation-commit auth-id ${this.authId}`;
  }
}
