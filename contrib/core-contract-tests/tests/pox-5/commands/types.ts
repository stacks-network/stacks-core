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

/** Mirrors a `protocol-bonds` row (the config `setup-bond` stores). */
export type BondConfig = {
  targetRate: bigint;
  stxValueRatio: bigint;
  minUstxRatio: bigint;
  earlyUnlockBytes: Uint8Array;
};

/** Mirrors a `protocol-bond-memberships` row. */
export type BondMembership = {
  bondIndex: bigint;
  amountUstx: bigint;
  signer: string;
  isL1Lock: boolean;
  amountSats: bigint;
};

export interface Model {
  /** Per-address staker state. Absent means not staking. */
  stakers: Map<string, StakerState>;
  // The next four maps mirror the contract's unconditional-write per-cycle
  // maps. Never pruned: past-cycle entries stay in place, which is what lets
  // the current cycle (frozen before any later update) read back correctly.
  /** Mirrors `ustx-delegated-per-cycle`. Cycle to total uSTX delegated. */
  ustxDelegatedPerCycle: Map<bigint, bigint>;
  /** Mirrors `signer-delegated-per-cycle`, keyed `${signer}|${cycle}`. */
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
  // The next three maps mirror the bond (some bond-index) variants of the
  // shares maps, which `add/remove-staker-from-bond-for-cycle` always move
  // (not threshold gated), so they are fully derivable. The none variant of
  // these maps is threshold gated and stays out of scope.
  /**
   * Mirrors `total-shares-staked-for-cycle` (some bond-index), keyed
   * `${cycle}|${bondIndex}` to total sats staked in that bond that cycle.
   */
  bondTotalSharesForCycle: Map<string, bigint>;
  /**
   * Mirrors `signer-shares-staked-for-cycle` (some bond-index), keyed
   * `${cycle}|${bondIndex}|${signer}` to the signer's sats that cycle.
   */
  bondSignerSharesForCycle: Map<string, bigint>;
  /**
   * Mirrors `staker-shares-staked-for-cycle` (some bond-index), keyed
   * `${cycle}|${bondIndex}|${signer}|${staker}` to the staker's sats that
   * cycle. Set absolute on add, zeroed (not deleted) on remove.
   */
  bondStakerSharesForCycle: Map<string, bigint>;
  /**
   * Every signer-manager contract deployed so far. `size` names the next
   * deploy.
   */
  deployedSigners: Set<string>;
  /**
   * Subset of `deployedSigners` registered with a key grant, mapped to the key
   * currently recorded for it (the contract's `signers` map value, set by
   * `register-signer`). A key rotation overwrites the value in place.
   */
  signers: Map<string, { signerKey: Uint8Array }>;
  /**
   * Serialised `${hex(signerKey)}|${signerManager}|${authId}` tuples consumed
   * via `grant-signer-key` (the contract's `used-signer-key-grants` map).
   * Never deleted, so replaying any of these must reject.
   */
  usedGrants: Set<string>;
  /**
   * Serialised `${hex(signerKey)}|${signerManager}` tuples currently live in
   * the contract's `signer-key-grants` map. A key rotation leaves the previous
   * grant live until it is explicitly revoked.
   */
  activeGrants: Set<string>;
  /** Current simulated burn block height. */
  burnBlockHeight: bigint;
  /** Burnchain parameters mirrored from `set-burnchain-parameters`. */
  rewardCycleLength: bigint;
  firstBurnHeight: bigint;
  prepareCycleLength: bigint;
  /** Mirrors `protocol-bonds`: bond-index to config; never deleted. */
  bonds: Map<bigint, BondConfig>;
  /**
   * Mirrors `protocol-bond-allowances`, keyed `${bondIndex}|${staker}` to
   * max-sats. One entry per allowlisted staker.
   */
  bondAllowances: Map<string, bigint>;
  /**
   * `first-bond-period-cycle` (= `begin-pox5-reward-cycle`). Bond `N` starts at
   * cycle `firstBondPeriodCycle + N * BOND_GAP_CYCLES`.
   */
  firstBondPeriodCycle: bigint;
  /** Per-principal sBTC balance, mirroring the sbtc-token ledger. */
  sbtcBalances: Map<string, bigint>;
  /** Mirrors the contract's `total-sbtc-staked` var. */
  totalSbtcStaked: bigint;
  /** Mirrors `protocol-bond-memberships`: staker to bond membership. */
  bondMemberships: Map<string, BondMembership>;
  /** Mirrors `protocol-bonds-total-staked`: bond-index to total sats. */
  bondTotalStaked: Map<bigint, bigint>;
  /** Command execution counts, for the end-of-run report. */
  statistics: Map<string, number>;
}
