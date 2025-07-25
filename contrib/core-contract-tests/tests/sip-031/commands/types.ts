import { accounts, project } from "../../clarigen-types";
import { projectFactory } from "@clarigen/core";

const contracts = projectFactory(project, "simnet");

export type Real = {
  accounts: typeof accounts;
  contracts: typeof contracts;
};

export interface Model {
  // Total STX balance currently held by SIP-031.
  balance: bigint;
  // Current block height used for vesting calculations.
  blockHeight: bigint;
  // SIP-031 constants including vesting parameters and error codes.
  constants: typeof contracts.sip031.constants;
  // Block height that marks when vesting becomes active.
  deployBlockHeight: bigint;
  // Flag indicating whether the initial funding has been transferred.
  initialized: boolean;
  // Current recipient address eligible to claim STX and update the recipient.
  recipient: string;
  // Running total of all STX that have been claimed from the contract.
  totalClaimed: bigint;
  // Map tracking command execution statistics for reporting purposes.
  statistics: Map<string, number>;
}
