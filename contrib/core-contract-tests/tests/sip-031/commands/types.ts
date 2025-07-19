import { accounts, project } from "../../clarigen-types";
import { projectFactory } from "@clarigen/core";

const contracts = projectFactory(project, "simnet");

export type Real = {
  accounts: typeof accounts;
  contracts: typeof contracts;
};

export interface Model {
  balance: bigint;
  blockHeight: bigint;
  constants: typeof contracts.sip031.constants;
  deployBlockHeight: bigint;
  initialized: boolean;
  recipient: string;
  totalClaimed: bigint;
  statistics: Map<string, number>;
}
