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
   * Per-cycle aggregate state mirroring the contract's four
   * unconditional-write maps, so any cycle (past, current, or future) is
   * checked against the value stored for that cycle. Never pruned: the
   * contract leaves past-cycle entries in place, which is what lets the
   * current cycle (frozen before any later update) read back correctly.
   */
  /** Mirrors `ustx-delegated-per-cycle`: Maps cycle to total uSTX delegated. */
  ustxDelegatedPerCycle: Map<bigint, bigint>;
  /** Mirrors `signer-delegated-per-cycle`. Maps `${signer}|${cycle}` to uSTX
   * amount.
   */
  signerDelegatedPerCycle: Map<string, bigint>;
  /** Mirrors `staker-signer-cycle-memberships`, keyed `${staker}|${cycle}`. */
  stakerSignerCycleMemberships: Map<
    string,
    { amountUstx: bigint; signer: string }
  >;
  /**
   * Mirrors `staker-shares-staked-for-cycle` (is-bond=false). Maps
   * `${staker}|${signer}|${cycle}` to uSTX amount.
   */
  stakerSharesStakedForCycle: Map<string, bigint>;
  /**
   * Identifiers of every signer-manager contract deployed so far.
   * `size` is the index used for naming the next deploy.
   */
  deployedSigners: Set<string>;
  /**
   * Subset of `deployedSigners` that has been registered with a key grant,
   * mapped to the signer key currently recorded for it (the value of the
   * contract's `signers` map, set by `register-signer`). `RotateSignerKey`
   * overwrites the key in place.
   */
  signers: Map<string, { signerKey: Uint8Array }>;
  /**
   * Serialised `${hex(signerKey)}|${signerManager}|${authId}` tuples consumed
   * via `grant-signer-key` (the contract's `used-signer-key-grants` map).
   * Never deleted: replaying any of these must reject with the proper error
   * code. Use `usedGrantKey` / `parseUsedGrantKey` to (de)serialise.
   */
  usedGrants: Set<string>;
  /**
   * Serialised `${hex(signerKey)}|${signerManager}` tuples currently live in
   * the contract's `signer-key-grants` map. Rotating a key leaves the previous
   * grant live until it is explicitly revoked.
   */
  activeGrants: Set<string>;
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
