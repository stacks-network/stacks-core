import fc from "fast-check";
import ololog from "ololog";

import { Simnet } from "@hirosystems/clarinet-sdk";
import { StacksPrivateKey } from "@stacks/transactions";
import { StackingClient } from "@stacks/stacking";

export type StxAddress = string;
export type BtcAddress = string;

export type Stub = {
  stackingMinimum: number;
  wallets: Map<StxAddress, Wallet>;
};

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

  ololog.configure({ locate: false })(prettyPrint.join(""));
};
