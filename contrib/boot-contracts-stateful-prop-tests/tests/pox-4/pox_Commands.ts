import fc from "fast-check";
import { Real, Stacker, Stub, StxAddress, Wallet } from "./pox_CommandModel";
import { GetStackingMinimumCommand } from "./pox_GetStackingMinimumCommand";
import { GetStxAccountCommand } from "./pox_GetStxAccountCommand";
import { StackStxSigCommand } from "./pox_StackStxSigCommand";
import { StackStxAuthCommand } from "./pox_StackStxAuthCommand";
import { DelegateStxCommand } from "./pox_DelegateStxCommand";
import { DelegateStackStxCommand } from "./pox_DelegateStackStxCommand";
import { Simnet } from "@hirosystems/clarinet-sdk";
import { Cl, cvToValue, OptionalCV, UIntCV } from "@stacks/transactions";
import { RevokeDelegateStxCommand } from "./pox_RevokeDelegateStxCommand";
import { AllowContractCallerCommand } from "./pox_AllowContractCallerCommand";
import { DelegateStackIncreaseCommand } from "./pox_DelegateStackIncreaseCommand";
import { DelegateStackExtendCommand } from "./pox_DelegateStackExtendCommand";
import { StackAggregationCommitAuthCommand } from "./pox_StackAggregationCommitAuthCommand";
import { StackAggregationCommitSigCommand } from "./pox_StackAggregationCommitSigCommand";
import { StackAggregationCommitIndexedSigCommand } from "./pox_StackAggregationCommitIndexedSigCommand";
import { StackAggregationCommitIndexedAuthCommand } from "./pox_StackAggregationCommitIndexedAuthCommand";
import { StackAggregationIncreaseCommand } from "./pox_StackAggregationIncreaseCommand";
import { DisallowContractCallerCommand } from "./pox_DisallowContractCallerCommand";
import { StackExtendAuthCommand } from "./pox_StackExtendAuthCommand";
import { StackExtendSigCommand } from "./pox_StackExtendSigCommand";
import { StackIncreaseAuthCommand } from "./pox_StackIncreaseAuthCommand";
import { StackIncreaseSigCommand } from "./pox_StackIncreaseSigCommand";

export function PoxCommands(
  wallets: Map<StxAddress, Wallet>,
  stackers: Map<StxAddress, Stacker>,
  network: Simnet,
): fc.Arbitrary<Iterable<fc.Command<Stub, Real>>> {
  const cmds = [
    // GetStackingMinimumCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
    }).map((
      r: {
        wallet: Wallet;
      },
    ) =>
      new GetStackingMinimumCommand(
        r.wallet,
      )
    ),
    // StackStxSigCommand
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
      new StackStxSigCommand(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
      )
    ),
    // StackStxAuthCommand
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
      new StackStxAuthCommand(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
      )
    ),
    // StackExtendAuthCommand
    fc
      .record({
        wallet: fc.constantFrom(...wallets.values()),
        authId: fc.nat(),
        extendCount: fc.integer({ min: 1, max: 12 }),
        currentCycle: fc.constant(currentCycle(network)),
      })
      .map(
        (r: {
          wallet: Wallet;
          extendCount: number;
          authId: number;
          currentCycle: number;
        }) =>
          new StackExtendAuthCommand(
            r.wallet,
            r.extendCount,
            r.authId,
            r.currentCycle,
          ),
      ),
    // StackExtendSigCommand
    fc
      .record({
        wallet: fc.constantFrom(...wallets.values()),
        authId: fc.nat(),
        extendCount: fc.integer({ min: 1, max: 12 }),
        currentCycle: fc.constant(currentCycle(network)),
      })
      .map(
        (r: {
          wallet: Wallet;
          extendCount: number;
          authId: number;
          currentCycle: number;
        }) =>
          new StackExtendSigCommand(
            r.wallet,
            r.extendCount,
            r.authId,
            r.currentCycle,
          ),
      ),
    // StackIncreaseAuthCommand
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.nat(),
      authId: fc.nat(),
    })
      .map((r) => {
        return new StackIncreaseAuthCommand(
          r.operator,
          r.increaseBy,
          r.authId,
        );
      }),
    // StackIncreaseSigCommand
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.nat(),
      authId: fc.nat(),
    })
      .map((r) => {
        return new StackIncreaseSigCommand(
          r.operator,
          r.increaseBy,
          r.authId,
        );
      }),
    // GetStackingMinimumCommand
    fc
      .record({
        wallet: fc.constantFrom(...wallets.values()),
      })
      .map((r: { wallet: Wallet }) => new GetStackingMinimumCommand(r.wallet)),
    // DelegateStxCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      delegateTo: fc.constantFrom(...wallets.values()),
      untilBurnHt: fc.integer({ min: 1 }),
      amount: fc.bigInt({ min: 0n, max: 100_000_000_000_000n }),
    }).map((
      r: {
        wallet: Wallet;
        delegateTo: Wallet;
        untilBurnHt: number;
        amount: bigint;
      },
    ) =>
      new DelegateStxCommand(
        r.wallet,
        r.delegateTo,
        r.untilBurnHt,
        r.amount,
      )
    ),
    // StackAggregationCommitAuthCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
      },
    ) =>
      new StackAggregationCommitAuthCommand(
        r.wallet,
        r.authId,
      )
    ),
    // StackAggregationCommitSigCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
      },
    ) =>
      new StackAggregationCommitSigCommand(
        r.wallet,
        r.authId,
      )
    ),
    // StackAggregationCommitIndexedAuthCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
      },
    ) =>
      new StackAggregationCommitIndexedAuthCommand(
        r.wallet,
        r.authId,
      )
    ),
    // StackAggregationCommitIndexedSigCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
      },
    ) =>
      new StackAggregationCommitIndexedSigCommand(
        r.wallet,
        r.authId,
      )
    ),
    // StackAggregationIncreaseCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
    }).chain((r) => {
      const operator = stackers.get(r.wallet.stxAddress)!;
      const committedRewCycleIndexesOrFallback =
        operator.committedRewCycleIndexes.length > 0
          ? operator.committedRewCycleIndexes
          : [-1];
      return fc.record({
        rewardCycleIndex: fc.constantFrom(
          ...committedRewCycleIndexesOrFallback,
        ),
      }).map((cycleIndex) => ({ ...r, ...cycleIndex }));
    }).map((
      r: {
        wallet: Wallet;
        rewardCycleIndex: number;
        authId: number;
      },
    ) =>
      new StackAggregationIncreaseCommand(
        r.wallet,
        r.rewardCycleIndex,
        r.authId,
      )
    ),
    // RevokeDelegateStxCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
    }).map((
      r: {
        wallet: Wallet;
      },
    ) =>
      new RevokeDelegateStxCommand(
        r.wallet,
      )
    ),
    // DelegateStackStxCommand
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
      return new DelegateStackStxCommand(
        finalResult.operator,
        finalResult.stacker,
        finalResult.period,
        finalResult.amount,
        finalResult.unlockBurnHt,
      );
    }),
    // DelegateStackIncreaseCommand
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      increaseBy: fc.nat(),
    })
      .chain((r) => {
        const operator = stackers.get(r.operator.stxAddress)!;
        const delegatorsList = operator.poolMembers;

        const availableStackers = delegatorsList.filter((delegator) => {
          const delegatorWallet = stackers.get(delegator)!;
          return delegatorWallet.unlockHeight > nextCycleFirstBlock(network);
        });

        const availableStackersOrFallback = availableStackers.length === 0
          ? [r.operator.stxAddress]
          : availableStackers;

        return fc
          .record({
            stacker: fc.constantFrom(...availableStackersOrFallback),
          })
          .map((stacker) => ({
            ...r,
            stacker: wallets.get(stacker.stacker)!,
          }));
      })
      .map((final) => {
        return new DelegateStackIncreaseCommand(
          final.operator,
          final.stacker,
          final.increaseBy,
        );
      }),
    // DelegateStackExtendCommand
    fc.record({
      operator: fc.constantFrom(...wallets.values()),
      extendCount: fc.integer({ min: 1, max: 11 }),
    }).chain((r) => {
      const operator = stackers.get(r.operator.stxAddress)!;
      const delegatorsList = operator.poolMembers;
      const availableStackers = delegatorsList.filter((delegator) => {
        const delegatorWallet = stackers.get(delegator)!;
        return delegatorWallet.unlockHeight > nextCycleFirstBlock(network);
      });

      const availableStackersOrFallback = availableStackers.length === 0
        ? [r.operator.stxAddress]
        : availableStackers;

      return fc.record({
        stacker: fc.constantFrom(...availableStackersOrFallback),
        currentCycle: fc.constant(currentCycle(network)),
      })
        .map((additionalProps) => ({
          ...r,
          stacker: wallets.get(additionalProps.stacker)!,
          currentCycle: additionalProps.currentCycle,
        }));
    }).map((final) =>
      new DelegateStackExtendCommand(
        final.operator,
        final.stacker,
        final.extendCount,
        final.currentCycle,
      )
    ),
    // AllowContractCallerCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      allowanceTo: fc.constantFrom(...wallets.values()),
      alllowUntilBurnHt: fc.oneof(
        fc.constant(Cl.none()),
        fc.integer({ min: 1 }).map((value) => Cl.some(Cl.uint(value))),
      ),
    })
      .map(
        (r: {
          wallet: Wallet;
          allowanceTo: Wallet;
          alllowUntilBurnHt: OptionalCV<UIntCV>;
        }) =>
          new AllowContractCallerCommand(
            r.wallet,
            r.allowanceTo,
            r.alllowUntilBurnHt,
          ),
      ),
    // DisallowContractCallerCommand
    fc.record({
      stacker: fc.constantFrom(...wallets.values()),
      callerToDisallow: fc.constantFrom(...wallets.values()),
    }).map(
      (r: {
        stacker: Wallet;
        callerToDisallow: Wallet;
      }) =>
        new DisallowContractCallerCommand(
          r.stacker,
          r.callerToDisallow,
        ),
    ),
    // GetStxAccountCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
    }).map((
      r: {
        wallet: Wallet;
      },
    ) =>
      new GetStxAccountCommand(
        r.wallet,
      )
    ),
  ];

  // More on size: https://github.com/dubzzz/fast-check/discussions/2978
  // More on cmds: https://github.com/dubzzz/fast-check/discussions/3026
  return fc.commands(cmds, { size: "xsmall" });
}

export const REWARD_CYCLE_LENGTH = 1050;

export const FIRST_BURNCHAIN_BLOCK_HEIGHT = 0;

export const currentCycle = (network: Simnet) =>
  Number(cvToValue(
    network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "current-pox-reward-cycle",
      [],
      "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
    ).result,
  ));

export const currentCycleFirstBlock = (network: Simnet) =>
  Number(cvToValue(
    network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "reward-cycle-to-burn-height",
      [Cl.uint(currentCycle(network))],
      "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
    ).result,
  ));

const nextCycleFirstBlock = (network: Simnet) =>
  Number(cvToValue(
    network.callReadOnlyFn(
      "ST000000000000000000002AMW42H.pox-4",
      "reward-cycle-to-burn-height",
      [Cl.uint(currentCycle(network) + 1)],
      "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
    ).result,
  ));
