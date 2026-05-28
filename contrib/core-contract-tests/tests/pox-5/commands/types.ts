import { accounts, project } from '../../clarigen-types';
import { projectFactory } from '@clarigen/core';

const contracts = projectFactory(project, 'simnet');

export type Real = {
  accounts: typeof accounts;
  contracts: typeof contracts;
  network: typeof simnet;
};

export type StakerState = {
  amountUstx: bigint;
  firstRewardCycle: bigint;
  numCycles: bigint;
  unlockBurnHeight: bigint;
  unlockCycle: bigint;
  signer: string;
};

export interface Model {
  /** Tracks per-address staker state. Absent means not staking. */
  stakers: Map<string, StakerState>;
  /**
   * Identifiers of every signer-manager contract deployed so far.
   * `size` is the index used for naming the next deploy.
   */
  deployedSigners: Set<string>;
  /** Subset of `deployedSigners` that has been registered with a key grant. */
  signers: Set<string>;
  /** Current simulated burn block height. */
  burnBlockHeight: bigint;
  /** Reward cycle length (set by setBurnchainParameters). */
  rewardCycleLength: bigint;
  /** First burn height (set by setBurnchainParameters). */
  firstBurnHeight: bigint;
  /** Prepare cycle length (set by setBurnchainParameters). */
  prepareCycleLength: bigint;
  /** Map tracking command execution counts for reporting. */
  statistics: Map<string, number>;
}
