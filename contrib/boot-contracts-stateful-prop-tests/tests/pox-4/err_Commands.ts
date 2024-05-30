import fc from "fast-check";
import {
  PoxCommand,
  Stacker,
  Stub,
  StxAddress,
  Wallet,
} from "./pox_CommandModel";
import { StackStxSigCommand_Err } from "./pox_StackStxSigCommand_Err";
import { StackStxAuthCommand_Err } from "./pox_StackStxAuthCommand_Err";
import { Simnet } from "@hirosystems/clarinet-sdk";
import { RevokeDelegateStxCommand_Err } from "./pox_RevokeDelegateStxCommand_Err";
import { DelegateStxCommand_Err } from "./pox_DelegateStxCommand_Err";
import { StackAggregationCommitSigCommand_Err } from "./pox_StackAggregationCommitSigCommand_Err";
import { StackAggregationCommitAuthCommand_Err } from "./pox_StackAggregationCommitAuthCommand_Err";
import { StackAggregationCommitIndexedSigCommand_Err } from "./pox_StackAggregationCommitIndexedSigCommand_Err";
import { StackAggregationCommitIndexedAuthCommand_Err } from "./pox_StackAggregationCommitIndexedAuthCommand_Err";
import { StackAggregationIncreaseCommand_Err } from "./pox_StackAggregationIncreaseCommand_Err";
import {
  currentCycle,
  currentCycleFirstBlock,
  FIRST_BURNCHAIN_BLOCK_HEIGHT,
  nextCycleFirstBlock,
  REWARD_CYCLE_LENGTH,
} from "./pox_Commands";
import { DelegateStackStxCommand_Err } from "./pox_DelegateStackStxCommand_Err";
import { StackIncreaseSigCommand_Err } from "./pox_StackIncreaseSigCommand_Err";
import { StackIncreaseAuthCommand_Err } from "./pox_StackIncreaseAuthCommand_Err";
import { StackExtendSigCommand_Err } from "./pox_StackExtendSigCommand_Err";
import { StackExtendAuthCommand_Err } from "./pox_StackExtendAuthCommand_Err";

const POX_4_ERRORS = {
  ERR_STACKING_INSUFFICIENT_FUNDS: 1,
  ERR_STACKING_INVALID_LOCK_PERIOD: 2,
  ERR_STACKING_ALREADY_STACKED: 3,
  ERR_STACKING_NO_SUCH_PRINCIPAL: 4,
  ERR_STACKING_PERMISSION_DENIED: 9,
  ERR_STACKING_THRESHOLD_NOT_MET: 11,
  ERR_STACKING_INVALID_AMOUNT: 18,
  ERR_STACKING_ALREADY_DELEGATED: 20,
  ERR_DELEGATION_TOO_MUCH_LOCKED: 22,
  ERR_STACK_EXTEND_NOT_LOCKED: 26,
  ERR_STACKING_IS_DELEGATED: 30,
  ERR_DELEGATION_ALREADY_REVOKED: 34,
};

export function ErrCommands(
  wallets: Map<StxAddress, Wallet>,
  stackers: Map<StxAddress, Stacker>,
  network: Simnet,
): fc.Arbitrary<PoxCommand>[] {
  const cmds = [
    // StackStxAuthCommand_Err_Stacking_Already_Stacked_1
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      period: fc.integer({ min: 1, max: 12 }),
      margin: fc.integer({ min: 1, max: 9 }),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
        period: number;
        margin: number;
      },
    ) =>
      new StackStxAuthCommand_Err(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
        function (
          this: StackStxAuthCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            stacker.isStacking &&
            !stacker.hasDelegated
          ) {
            model.trackCommandRun(
              "StackStxAuthCommand_Err_Stacking_Already_Stacked_1",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_STACKING_ALREADY_STACKED,
      )
    ),
    // StackStxAuthCommand_Err_Stacking_Already_Stacked_2
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      period: fc.integer({ min: 1, max: 12 }),
      margin: fc.integer({ min: 1, max: 9 }),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
        period: number;
        margin: number;
      },
    ) =>
      new StackStxAuthCommand_Err(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
        function (
          this: StackStxAuthCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            stacker.isStacking &&
            stacker.hasDelegated
          ) {
            model.trackCommandRun(
              "StackStxAuthCommand_Err_Stacking_Already_Stacked_2",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_STACKING_ALREADY_STACKED,
      )
    ),
    // StackStxAuthCommand_Err_Stacking_Already_Delegated
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      period: fc.integer({ min: 1, max: 12 }),
      margin: fc.integer({ min: 1, max: 9 }),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
        period: number;
        margin: number;
      },
    ) =>
      new StackStxAuthCommand_Err(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
        function (
          this: StackStxAuthCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            !stacker.isStacking &&
            stacker.hasDelegated
          ) {
            model.trackCommandRun(
              "StackStxAuthCommand_Err_Stacking_Already_Delegated",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_STACKING_ALREADY_DELEGATED,
      )
    ),
    // StackStxSigCommand_Err_Stacking_Already_Stacked_1
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      period: fc.integer({ min: 1, max: 12 }),
      margin: fc.integer({ min: 1, max: 9 }),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
        period: number;
        margin: number;
      },
    ) =>
      new StackStxSigCommand_Err(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
        function (
          this: StackStxSigCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            stacker.isStacking &&
            !stacker.hasDelegated
          ) {
            model.trackCommandRun(
              "StackStxSigCommand_Err_Stacking_Already_Stacked_1",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_STACKING_ALREADY_STACKED,
      )
    ),
    // StackStxSigCommand_Err_Stacking_Already_Stacked_2
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      period: fc.integer({ min: 1, max: 12 }),
      margin: fc.integer({ min: 1, max: 9 }),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
        period: number;
        margin: number;
      },
    ) =>
      new StackStxSigCommand_Err(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
        function (
          this: StackStxSigCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            stacker.isStacking &&
            stacker.hasDelegated
          ) {
            model.trackCommandRun(
              "StackStxSigCommand_Err_Stacking_Already_Stacked_2",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_STACKING_ALREADY_STACKED,
      )
    ),
    // StackStxSigCommand_Err_Stacking_Already_Delegated
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      period: fc.integer({ min: 1, max: 12 }),
      margin: fc.integer({ min: 1, max: 9 }),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
        period: number;
        margin: number;
      },
    ) =>
      new StackStxSigCommand_Err(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
        function (
          this: StackStxSigCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            !stacker.isStacking &&
            stacker.hasDelegated
          ) {
            model.trackCommandRun(
              "StackStxSigCommand_Err_Stacking_Already_Delegated",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_STACKING_ALREADY_DELEGATED,
      )
    ),
    // RevokeDelegateStxCommand_Err_Delegation_Already_Revoked
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
    }).map((
      r: {
        wallet: Wallet;
      },
    ) =>
      new RevokeDelegateStxCommand_Err(
        r.wallet,
        function (
          this: RevokeDelegateStxCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            !stacker.hasDelegated
          ) {
            model.trackCommandRun(
              "RevokeDelegateStxCommand_Err_Delegation_Already_Revoked",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_DELEGATION_ALREADY_REVOKED,
      )
    ),
    // DelegateStxCommand_Err_Stacking_Already_Delegated
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      delegateTo: fc.constantFrom(...wallets.values()),
      untilBurnHt: fc.integer({ min: 1 }),
      amount: fc.bigInt({ min: 0n, max: 100_000_000_000_000n }),
    })
      .map((
        r: {
          wallet: Wallet;
          delegateTo: Wallet;
          untilBurnHt: number;
          amount: bigint;
        },
      ) =>
        new DelegateStxCommand_Err(
          r.wallet,
          r.delegateTo,
          r.untilBurnHt,
          r.amount,
          function (
            this: DelegateStxCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;
            if (
              model.stackingMinimum > 0 &&
              stacker.hasDelegated
            ) {
              model.trackCommandRun(
                "DelegateStxCommand_Err_Stacking_Already_Delegated",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_ALREADY_DELEGATED,
        )
      ),
    // StackAggregationCommitSigCommand_Err_Stacking_Threshold_Not_Met
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitSigCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              operator.lockedAddresses.length > 0 &&
              !(operator.amountToCommit >= model.stackingMinimum) &&
              operator.amountToCommit > 0
            ) {
              model.trackCommandRun(
                "StackAggregationCommitSigCommand_Err_Stacking_Threshold_Not_Met",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_THRESHOLD_NOT_MET,
        ),
    ),
    // StackAggregationCommitSigCommand_Err_Stacking_No_Such_Principal_1
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitSigCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              operator.lockedAddresses.length > 0 &&
              !(operator.amountToCommit >= model.stackingMinimum) &&
              operator.amountToCommit === 0
            ) {
              model.trackCommandRun(
                "StackAggregationCommitSigCommand_Err_Stacking_No_Such_Principal_1",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // StackAggregationCommitSigCommand_Err_Stacking_No_Such_Principal_2
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitSigCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              !(operator.lockedAddresses.length > 0) &&
              !(operator.amountToCommit >= model.stackingMinimum)
            ) {
              model.trackCommandRun(
                "StackAggregationCommitSigCommand_Err_Stacking_No_Such_Principal_2",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // StackAggregationCommitAuthCommand_Err_Stacking_Threshold_Not_Met
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitAuthCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              operator.lockedAddresses.length > 0 &&
              !(operator.amountToCommit >= model.stackingMinimum) &&
              operator.amountToCommit > 0
            ) {
              model.trackCommandRun(
                "StackAggregationCommitAuthCommand_Err_Stacking_Threshold_Not_Met",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_THRESHOLD_NOT_MET,
        ),
    ),
    // StackAggregationCommitAuthCommand_Err_Stacking_No_Such_Principal_1
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitAuthCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              operator.lockedAddresses.length > 0 &&
              !(operator.amountToCommit >= model.stackingMinimum) &&
              operator.amountToCommit === 0
            ) {
              model.trackCommandRun(
                "StackAggregationCommitAuthCommand_Err_Stacking_No_Such_Principal_1",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // StackAggregationCommitAuthCommand_Err_Stacking_No_Such_Principal_2
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitAuthCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              !(operator.lockedAddresses.length > 0) &&
              !(operator.amountToCommit >= model.stackingMinimum)
            ) {
              model.trackCommandRun(
                "StackAggregationCommitAuthCommand_Err_Stacking_No_Such_Principal_2",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // StackAggregationCommitIndexedSigCommand_Err_Stacking_Threshold_Not_Met
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitIndexedSigCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitIndexedSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              operator.lockedAddresses.length > 0 &&
              !(operator.amountToCommit >= model.stackingMinimum) &&
              operator.amountToCommit > 0
            ) {
              model.trackCommandRun(
                "StackAggregationCommitIndexedSigCommand_Err_Stacking_Threshold_Not_Met",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_THRESHOLD_NOT_MET,
        ),
    ),
    // StackAggregationCommitIndexedSigCommand_Err_Stacking_No_Such_Principal_1
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitIndexedSigCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitIndexedSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              operator.lockedAddresses.length > 0 &&
              !(operator.amountToCommit >= model.stackingMinimum) &&
              !(operator.amountToCommit > 0)
            ) {
              model.trackCommandRun(
                "StackAggregationCommitIndexedSigCommand_Err_Stacking_No_Such_Principal_1",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // StackAggregationCommitIndexedSigCommand_Err_Stacking_No_Such_Principal_2
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitIndexedSigCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitIndexedSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              !(operator.lockedAddresses.length > 0) &&
              !(operator.amountToCommit >= model.stackingMinimum)
            ) {
              model.trackCommandRun(
                "StackAggregationCommitIndexedSigCommand_Err_Stacking_No_Such_Principal_2",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // StackAggregationCommitIndexedAuthCommand_Err_Stacking_No_Such_Principal_1
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitIndexedAuthCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitIndexedAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              operator.lockedAddresses.length > 0 &&
              !(operator.amountToCommit >= model.stackingMinimum) &&
              !(operator.amountToCommit > 0)
            ) {
              model.trackCommandRun(
                "StackAggregationCommitIndexedAuthCommand_Err_Stacking_No_Such_Principal_1",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // StackAggregationCommitIndexedAuthCommand_Err_Stacking_No_Such_Principal_2
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitIndexedAuthCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitIndexedAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              !(operator.lockedAddresses.length > 0) &&
              !(operator.amountToCommit >= model.stackingMinimum)
            ) {
              model.trackCommandRun(
                "StackAggregationCommitIndexedAuthCommand_Err_Stacking_No_Such_Principal_2",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // StackAggregationCommitIndexedAuthCommand_Err_Stacking_Threshold_Not_Met
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map(
      (r: { wallet: Wallet; authId: number }) =>
        new StackAggregationCommitIndexedAuthCommand_Err(
          r.wallet,
          r.authId,
          function (
            this: StackAggregationCommitIndexedAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;

            if (
              operator.lockedAddresses.length > 0 &&
              !(operator.amountToCommit >= model.stackingMinimum) &&
              operator.amountToCommit > 0
            ) {
              model.trackCommandRun(
                "StackAggregationCommitIndexedAuthCommand_Err_Stacking_Threshold_Not_Met",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_THRESHOLD_NOT_MET,
        ),
    ),
    // StackAggregationIncreaseCommand_Err_Stacking_No_Such_Principal
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).chain((r) => {
      const operator = stackers.get(r.wallet.stxAddress)!;
      const committedRewCycleIndexesOrFallback =
        operator.committedRewCycleIndexes.length > 0
          ? operator.committedRewCycleIndexes
          : [-1];
      return fc
        .record({
          rewardCycleIndex: fc.constantFrom(
            ...committedRewCycleIndexesOrFallback,
          ),
        })
        .map((cycleIndex) => ({ ...r, ...cycleIndex }));
    }).map(
      (r: { wallet: Wallet; rewardCycleIndex: number; authId: number }) =>
        new StackAggregationIncreaseCommand_Err(
          r.wallet,
          r.rewardCycleIndex,
          r.authId,
          function (
            this: StackAggregationIncreaseCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const operator = model.stackers.get(this.operator.stxAddress)!;
            if (
              operator.lockedAddresses.length > 0 &&
              this.rewardCycleIndex >= 0 &&
              !(operator.amountToCommit > 0)
            ) {
              model.trackCommandRun(
                "StackAggregationIncreaseCommand_Err_Stacking_No_Such_Principal",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL,
        ),
    ),
    // DelegateStackStxCommand_Err_Delegation_Too_Much_Locked
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      startBurnHt: fc.integer({
        min: currentCycleFirstBlock(network),
        max: nextCycleFirstBlock(network),
      }),
      period: fc.integer({ min: 1, max: 12 }),
    }).chain((r) => {
      const operator = stackers.get(r.operator.stxAddress)!;
      // Determine available stackers based on the operator
      const availableStackers = operator.poolMembers.length > 0
        ? operator.poolMembers
        : [r.operator.stxAddress];

      return fc.record({
        stacker: fc.constantFrom(...availableStackers),
      }).map((stacker) => ({
        ...r,
        stacker: wallets.get(stacker.stacker)!,
      })).chain((resultWithStacker) => {
        return fc.record({
          unlockBurnHt: fc.constant(
            currentCycleFirstBlock(network) +
              1050 * (resultWithStacker.period + 1),
          ),
        }).map((additionalProps) => ({
          ...resultWithStacker,
          ...additionalProps,
        }));
      }).chain((resultWithUnlockHeight) => {
        return fc.record({
          amount: fc.bigInt({
            min: 0n,
            max: 100_000_000_000_000n,
          }),
        }).map((amountProps) => ({
          ...resultWithUnlockHeight,
          ...amountProps,
        }));
      });
    }).map((finalResult) => {
      return new DelegateStackStxCommand_Err(
        finalResult.operator,
        finalResult.stacker,
        finalResult.period,
        finalResult.amount,
        finalResult.unlockBurnHt,
        function (
          this: DelegateStackStxCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
          const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            !stackerWallet.isStacking &&
            stackerWallet.hasDelegated &&
            !(stackerWallet.delegatedMaxAmount >= Number(this.amountUstx)) &&
            Number(this.amountUstx) <= stackerWallet.ustxBalance &&
            Number(this.amountUstx) >= model.stackingMinimum &&
            operatorWallet.poolMembers.includes(this.stacker.stxAddress) &&
            this.unlockBurnHt <= stackerWallet.delegatedUntilBurnHt
          ) {
            model.trackCommandRun(
              "DelegateStackStxCommand_Err_Delegation_Too_Much_Locked",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_DELEGATION_TOO_MUCH_LOCKED,
      );
    }),
    // DelegateStackStxCommand_Err_Stacking_Permission_Denied
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      startBurnHt: fc.integer({
        min: currentCycleFirstBlock(network),
        max: nextCycleFirstBlock(network),
      }),
      period: fc.integer({ min: 1, max: 12 }),
    }).chain((r) => {
      const operator = stackers.get(r.operator.stxAddress)!;
      // Determine available stackers based on the operator
      const availableStackers = operator.poolMembers.length > 0
        ? operator.poolMembers
        : [r.operator.stxAddress];

      return fc.record({
        stacker: fc.constantFrom(...availableStackers),
      }).map((stacker) => ({
        ...r,
        stacker: wallets.get(stacker.stacker)!,
      })).chain((resultWithStacker) => {
        return fc.record({
          unlockBurnHt: fc.constant(
            currentCycleFirstBlock(network) +
              1050 * (resultWithStacker.period + 1),
          ),
        }).map((additionalProps) => ({
          ...resultWithStacker,
          ...additionalProps,
        }));
      }).chain((resultWithUnlockHeight) => {
        return fc.record({
          amount: fc.bigInt({
            min: 0n,
            max: BigInt(
              stackers.get(resultWithUnlockHeight.stacker.stxAddress)!
                .delegatedMaxAmount,
            ),
          }),
        }).map((amountProps) => ({
          ...resultWithUnlockHeight,
          ...amountProps,
        }));
      });
    }).map((finalResult) => {
      return new DelegateStackStxCommand_Err(
        finalResult.operator,
        finalResult.stacker,
        finalResult.period,
        finalResult.amount,
        finalResult.unlockBurnHt,
        function (
          this: DelegateStackStxCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
          const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            !stackerWallet.isStacking &&
            stackerWallet.hasDelegated &&
            stackerWallet.delegatedMaxAmount >= Number(this.amountUstx) &&
            Number(this.amountUstx) <= stackerWallet.ustxBalance &&
            Number(this.amountUstx) >= model.stackingMinimum &&
            !operatorWallet.poolMembers.includes(this.stacker.stxAddress) &&
            this.unlockBurnHt <= stackerWallet.delegatedUntilBurnHt
          ) {
            model.trackCommandRun(
              "DelegateStackStxCommand_Err_Stacking_Permission_Denied_1",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_STACKING_PERMISSION_DENIED,
      );
    }),
    // DelegateStackStxCommand_Err_Stacking_Permission_Denied_2
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      startBurnHt: fc.integer({
        min: currentCycleFirstBlock(network),
        max: nextCycleFirstBlock(network),
      }),
      period: fc.integer({ min: 1, max: 12 }),
    }).chain((r) => {
      const operator = stackers.get(r.operator.stxAddress)!;
      // Determine available stackers based on the operator
      const availableStackers = operator.poolMembers.length > 0
        ? operator.poolMembers
        : [r.operator.stxAddress];

      return fc.record({
        stacker: fc.constantFrom(...availableStackers),
      }).map((stacker) => ({
        ...r,
        stacker: wallets.get(stacker.stacker)!,
      })).chain((resultWithStacker) => {
        return fc.record({
          unlockBurnHt: fc.constant(
            currentCycleFirstBlock(network) +
              1050 * (resultWithStacker.period + 1),
          ),
        }).map((additionalProps) => ({
          ...resultWithStacker,
          ...additionalProps,
        }));
      }).chain((resultWithUnlockHeight) => {
        return fc.record({
          amount: fc.bigInt({
            min: 0n,
            max: 100_000_000_000_000n,
          }),
        }).map((amountProps) => ({
          ...resultWithUnlockHeight,
          ...amountProps,
        }));
      });
    }).map((finalResult) => {
      return new DelegateStackStxCommand_Err(
        finalResult.operator,
        finalResult.stacker,
        finalResult.period,
        finalResult.amount,
        finalResult.unlockBurnHt,
        function (
          this: DelegateStackStxCommand_Err,
          model: Readonly<Stub>,
        ): boolean {
          const operatorWallet = model.stackers.get(this.operator.stxAddress)!;
          const stackerWallet = model.stackers.get(this.stacker.stxAddress)!;
          if (
            model.stackingMinimum > 0 &&
            !stackerWallet.isStacking &&
            !(stackerWallet.hasDelegated) &&
            !(stackerWallet.delegatedMaxAmount >= Number(this.amountUstx)) &&
            Number(this.amountUstx) <= stackerWallet.ustxBalance &&
            Number(this.amountUstx) >= model.stackingMinimum &&
            !(operatorWallet.poolMembers.includes(this.stacker.stxAddress)) &&
            !(this.unlockBurnHt <= stackerWallet.delegatedUntilBurnHt)
          ) {
            model.trackCommandRun(
              "DelegateStackStxCommand_Err_Stacking_Permission_Denied_2",
            );
            return true;
          } else return false;
        },
        POX_4_ERRORS.ERR_STACKING_PERMISSION_DENIED,
      );
    }),
    // StackIncreaseSigCommand_Err_Stacking_Is_Delegated
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.nat(),
      authId: fc.nat(),
    }).map(
      (r) =>
        new StackIncreaseSigCommand_Err(
          r.operator,
          r.increaseBy,
          r.authId,
          function (
            this: StackIncreaseSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              !stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              this.increaseBy <= stacker.amountUnlocked &&
              this.increaseBy >= 1
            ) {
              model.trackCommandRun(
                "StackIncreaseSigCommand_Err_Stacking_Is_Delegated",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_IS_DELEGATED,
        ),
    ),
    // StackIncreaseSigCommand_Err_Stacking_Insufficient_Funds
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.constant(100_000_000_000_000),
      authId: fc.nat(),
    }).map(
      (r) =>
        new StackIncreaseSigCommand_Err(
          r.operator,
          r.increaseBy,
          r.authId,
          function (
            this: StackIncreaseSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              !(this.increaseBy <= stacker.amountUnlocked) &&
              this.increaseBy >= 1
            ) {
              model.trackCommandRun(
                "StackIncreaseSigCommand_Err_Stacking_Insufficient_Funds",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_INSUFFICIENT_FUNDS,
        ),
    ),
    // StackIncreaseSigCommand_Err_Stacking_Invalid_Amount
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.constant(0),
      authId: fc.nat(),
    }).map(
      (r) =>
        new StackIncreaseSigCommand_Err(
          r.operator,
          r.increaseBy,
          r.authId,
          function (
            this: StackIncreaseSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              this.increaseBy <= stacker.amountUnlocked &&
              !(this.increaseBy >= 1)
            ) {
              model.trackCommandRun(
                "StackIncreaseSigCommand_Err_Stacking_Invalid_Amount",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_INVALID_AMOUNT,
        ),
    ),
    // StackIncreaseAuthCommand_Err_Stacking_Is_Delegated
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.nat(),
      authId: fc.nat(),
    }).map(
      (r) =>
        new StackIncreaseAuthCommand_Err(
          r.operator,
          r.increaseBy,
          r.authId,
          function (
            this: StackIncreaseAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              !stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              this.increaseBy <= stacker.amountUnlocked &&
              this.increaseBy >= 1
            ) {
              model.trackCommandRun(
                "StackIncreaseAuthCommand_Err_Stacking_Is_Delegated",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_IS_DELEGATED,
        ),
    ),
    // StackIncreaseAuthCommand_Err_Stacking_Insufficient_Funds
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.constant(100_000_000_000_000),
      authId: fc.nat(),
    }).map(
      (r) =>
        new StackIncreaseAuthCommand_Err(
          r.operator,
          r.increaseBy,
          r.authId,
          function (
            this: StackIncreaseAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              !(this.increaseBy <= stacker.amountUnlocked) &&
              this.increaseBy >= 1
            ) {
              model.trackCommandRun(
                "StackIncreaseAuthCommand_Err_Stacking_Insufficient_Funds",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_INSUFFICIENT_FUNDS,
        ),
    ),
    // StackIncreaseAuthCommand_Err_Stacking_Invalid_Amount
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.constant(0),
      authId: fc.nat(),
    }).map(
      (r) =>
        new StackIncreaseAuthCommand_Err(
          r.operator,
          r.increaseBy,
          r.authId,
          function (
            this: StackIncreaseAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              this.increaseBy <= stacker.amountUnlocked &&
              !(this.increaseBy >= 1)
            ) {
              model.trackCommandRun(
                "StackIncreaseAuthCommand_Err_Stacking_Invalid_Amount",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_INVALID_AMOUNT,
        ),
    ),
    // StackExtendSigCommand_Err_Stacking_Is_Delegated_1
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer({ min: 1, max: 12 }),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendSigCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              !stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              stacker.poolMembers.length === 0 &&
              totalPeriod <= 12
            ) {
              model.trackCommandRun(
                "StackExtendSigCommand_Err_Stacking_Is_Delegated_1",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_IS_DELEGATED,
        ),
    ),
    // StackExtendSigCommand_Err_Stacking_Is_Delegated_2
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer({ min: 1, max: 12 }),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendSigCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              !stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              !(stacker.poolMembers.length === 0) &&
              totalPeriod <= 12
            ) {
              model.trackCommandRun(
                "StackExtendSigCommand_Err_Stacking_Is_Delegated_2",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_IS_DELEGATED,
        ),
    ),
    // StackExtendSigCommand_Err_Stacking_Already_Delegated
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer({ min: 1, max: 12 }),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendSigCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              stacker.isStackingSolo &&
              stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              stacker.poolMembers.length === 0 &&
              totalPeriod <= 12
            ) {
              model.trackCommandRun(
                "StackExtendSigCommand_Err_Stacking_Already_Delegated",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_ALREADY_DELEGATED,
        ),
    ),
    // StackExtendSigCommand_Err_Stacking_Invalid_Lock_Period
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer(),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendSigCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              stacker.poolMembers.length === 0 &&
              !(totalPeriod <= 12)
            ) {
              model.trackCommandRun(
                "StackExtendSigCommand_Err_Stacking_Invalid_Lock_Period",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_INVALID_LOCK_PERIOD,
        ),
    ),
    // StackExtendSigCommand_Err_Stack_Extend_Not_Locked
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer({ min: 1, max: 12 }),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendSigCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendSigCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              !stacker.isStacking &&
              !stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              !(stacker.amountLocked > 0) &&
              stacker.poolMembers.length === 0 &&
              totalPeriod <= 12
            ) {
              model.trackCommandRun(
                "StackExtendSigCommand_Err_Stack_Extend_Not_Locked",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACK_EXTEND_NOT_LOCKED,
        ),
    ),
    // StackExtendAuthCommand_Err_Stacking_Is_Delegated_1
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer({ min: 1, max: 12 }),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendAuthCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              !stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              stacker.poolMembers.length === 0 &&
              totalPeriod <= 12
            ) {
              model.trackCommandRun(
                "StackExtendAuthCommand_Err_Stacking_Is_Delegated_1",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_IS_DELEGATED,
        ),
    ),
    // StackExtendAuthCommand_Err_Stacking_Is_Delegated_2
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer({ min: 1, max: 12 }),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendAuthCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              !stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              !(stacker.poolMembers.length === 0) &&
              totalPeriod <= 12
            ) {
              model.trackCommandRun(
                "StackExtendAuthCommand_Err_Stacking_Is_Delegated_2",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_IS_DELEGATED,
        ),
    ),
    // StackExtendAuthCommand_Err_Stacking_Already_Delegated
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer({ min: 1, max: 12 }),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendAuthCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              stacker.isStackingSolo &&
              stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              stacker.poolMembers.length === 0 &&
              totalPeriod <= 12
            ) {
              model.trackCommandRun(
                "StackExtendAuthCommand_Err_Stacking_Already_Delegated",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_ALREADY_DELEGATED,
        ),
    ),
    // StackExtendAuthCommand_Err_Stacking_Invalid_Lock_Period
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer(),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendAuthCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              stacker.isStacking &&
              stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              stacker.amountLocked > 0 &&
              stacker.poolMembers.length === 0 &&
              !(totalPeriod <= 12)
            ) {
              model.trackCommandRun(
                "StackExtendAuthCommand_Err_Stacking_Invalid_Lock_Period",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACKING_INVALID_LOCK_PERIOD,
        ),
    ),
    // StackExtendAuthCommand_Err_Stack_Extend_Not_Locked
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      extendCount: fc.integer({ min: 1, max: 12 }),
      currentCycle: fc.constant(currentCycle(network)),
    }).map(
      (r: {
        wallet: Wallet;
        extendCount: number;
        authId: number;
        currentCycle: number;
      }) =>
        new StackExtendAuthCommand_Err(
          r.wallet,
          r.extendCount,
          r.authId,
          r.currentCycle,
          function (
            this: StackExtendAuthCommand_Err,
            model: Readonly<Stub>,
          ): boolean {
            const stacker = model.stackers.get(this.wallet.stxAddress)!;

            const firstRewardCycle =
              stacker.firstLockedRewardCycle < this.currentCycle
                ? this.currentCycle
                : stacker.firstLockedRewardCycle;
            const firstExtendCycle = Math.floor(
              (stacker.unlockHeight - FIRST_BURNCHAIN_BLOCK_HEIGHT) /
                REWARD_CYCLE_LENGTH,
            );
            const lastExtendCycle = firstExtendCycle + this.extendCount - 1;
            const totalPeriod = lastExtendCycle - firstRewardCycle + 1;
            if (
              model.stackingMinimum > 0 &&
              !stacker.isStacking &&
              !stacker.isStackingSolo &&
              !stacker.hasDelegated &&
              !(stacker.amountLocked > 0) &&
              stacker.poolMembers.length === 0 &&
              totalPeriod <= 12
            ) {
              model.trackCommandRun(
                "StackExtendAuthCommand_Err_Stack_Extend_Not_Locked",
              );
              return true;
            } else return false;
          },
          POX_4_ERRORS.ERR_STACK_EXTEND_NOT_LOCKED,
        ),
    ),
  ];

  return cmds;
}
