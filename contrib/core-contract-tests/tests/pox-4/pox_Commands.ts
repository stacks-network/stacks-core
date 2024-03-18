import fc from "fast-check";
import { Real, Stub, StxAddress, Wallet } from "./pox_CommandModel";
import { GetStackingMinimumCommand } from "./pox_GetStackingMinimumCommand";
import { GetStxAccountCommand } from "./pox_GetStxAccountCommand";
import { StackStxCommand } from "./pox_StackStxCommand";
import { DelegateStxCommand } from "./pox_DelegateStxCommand";

export function PoxCommands(
  wallets: Map<StxAddress, Wallet>,
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
    // StackStxCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      authId: fc.nat(),
      period: fc.integer({ min: 1, max: 7 }),
      margin: fc.integer({ min: 2, max: 9 }),
    }).map((
      r: {
        wallet: Wallet;
        authId: number;
        period: number;
        margin: number;
      },
    ) =>
      new StackStxCommand(
        r.wallet,
        r.authId,
        r.period,
        r.margin,
      )
    ),
    // DelegateStxCommand
    fc.record({
      wallet: fc.constantFrom(...wallets.values()),
      delegateTo: fc.constantFrom(...wallets.values()),
      untilBurnHt: fc.integer({ min: 1 }),
      margin: fc.integer({ min: 2, max: 9 }),
    }).map((
      r: {
        wallet: Wallet;
        delegateTo: Wallet;
        untilBurnHt: number;
        margin: number;
      },
    ) =>
      new DelegateStxCommand(
        r.wallet,
        r.delegateTo,
        r.untilBurnHt,
        r.margin,
      )
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
  return fc.commands(cmds, { size: "large" });
}
