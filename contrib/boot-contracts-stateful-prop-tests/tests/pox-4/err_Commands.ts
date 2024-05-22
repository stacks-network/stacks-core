import fc from "fast-check";
import { PoxCommand, Stacker, Stub, StxAddress, Wallet } from "./pox_CommandModel";
import { StackStxSigCommand_Err } from "./pox_StackStxSigCommand_Err";
import { StackStxAuthCommand_Err } from "./pox_StackStxAuthCommand_Err";
import { Simnet } from "@hirosystems/clarinet-sdk";

export function ErrCommands(
  wallets: Map<StxAddress, Wallet>,
  stackers: Map<StxAddress, Stacker>,
  network: Simnet,
): fc.Arbitrary<PoxCommand>[] {
  const cmds = [
    // StackStxAuthCommand_Err
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
        function (this: StackStxAuthCommand_Err, model: Readonly<Stub>): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          return (
            model.stackingMinimum > 0 && !stacker.isStacking &&
            !stacker.hasDelegated
          );
        },
        123,
      )
    ),
    // StackStxSigCommand_Err
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
        function (this: StackStxSigCommand_Err, model: Readonly<Stub>): boolean {
          const stacker = model.stackers.get(this.wallet.stxAddress)!;
          return (
            model.stackingMinimum > 0 && !stacker.isStacking &&
            !stacker.hasDelegated
          );
        },
        123,
      )
    ),
  ];

  return cmds;
}
