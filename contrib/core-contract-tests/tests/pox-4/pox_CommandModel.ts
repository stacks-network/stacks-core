import fc from "fast-check";

import { Simnet } from "@hirosystems/clarinet-sdk";
import { StacksPrivateKey } from "@stacks/transactions";
import { StackingClient } from "@stacks/stacking";

export type StxAddress = string;
export type BtcAddress = string;
export type CommandTag = string;

export class Stub {
  readonly wallets: Map<StxAddress, Wallet>;
  readonly statistics: Map<string, number>;
  stackingMinimum: number;

  constructor(
    wallets: Map<StxAddress, Wallet>,
    statistics: Map<CommandTag, number>,
  ) {
    this.wallets = wallets;
    this.statistics = statistics;
    this.stackingMinimum = 0;
  }

  trackCommandRun(commandName: string) {
    const count = this.statistics.get(commandName) || 0;
    this.statistics.set(commandName, count + 1);
  }

  reportCommandRuns() {
    process.stdout.write("Command run method execution counts:");
    this.statistics.forEach((count, commandName) => {
      process.stdout.write(`\n${commandName}: ${count}`);
    });
  }
}

export type Real = {
  network: Simnet;
};

export type Wallet = {
  label: string;
  stxAddress: string;
  btcAddress: string;
  signerPrvKey: StacksPrivateKey;
  signerPubKey: string;
  stackingClient: StackingClient;
  ustxBalance: number;
  isStacking: boolean;
  hasDelegated: boolean;
  lockedAddresses: StxAddress[];
  poolMembers: StxAddress[];
  delegatedTo: StxAddress;
  delegatedMaxAmount: number;
  delegatedUntilBurnHt: number;
  delegatedPoxAddress: BtcAddress;
  amountLocked: number;
  amountUnlocked: number;
  unlockHeight: number;
  allowedContractCaller: StxAddress;
  callerAllowedBy: StxAddress[];
};

export type PoxCommand = fc.Command<Stub, Real>;

export const logCommand = (...items: (string | undefined)[]) => {
  // Ensure we only render up to the first 10 items for brevity.
  const renderItems = items.slice(0, 10);
  const columnWidth = 23;
  // Pad each column to the same width.
  const prettyPrint = renderItems.map((content) =>
    content ? content.padEnd(columnWidth) : "".padEnd(columnWidth)
  );
  prettyPrint.push("\n");

  process.stdout.write(prettyPrint.join(""));
};
