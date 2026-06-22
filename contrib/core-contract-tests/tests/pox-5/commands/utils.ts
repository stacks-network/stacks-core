import type { Model, Real, StakerState } from './types';
import { accounts } from '../../clarigen-types';
import {
  BOND_GAP_CYCLES,
  BOND_LENGTH_CYCLES,
  MAX_SIGNERS,
  POX5_BOOT_ID,
  PRECISION,
  RESERVE_RATIO,
  SIGNER_SET_MIN_USTX,
  sbtcBalance,
  testSigner,
} from '../pox-5-helpers';
import { rov, rovOk } from '@clarigen/test';
import { hex } from '@scure/base';
import { cvToValue, hexToCV } from '@stacks/transactions';
import { expect } from 'vitest';

export function currentRewardCycle(model: Readonly<Model>): bigint {
  return (
    (model.burnBlockHeight - model.firstBurnHeight) / model.rewardCycleLength
  );
}

export function rewardCycleToBurnHeight(
  model: Readonly<Model>,
  cycle: bigint,
): bigint {
  return model.firstBurnHeight + cycle * model.rewardCycleLength;
}

export function isStakerActive(
  model: Readonly<Model>,
  address: string,
): boolean {
  const staker = model.stakers.get(address);
  if (!staker) return false;
  // get-staker-info expires a lock once first + num <= current cycle.
  // unlockCycle holds first + num, so active means current < unlockCycle.
  return currentRewardCycle(model) < staker.unlockCycle;
}

/**
 * True when `staker` holds a position in the current reward cycle: its lock
 * has started (firstRewardCycle <= current) and not yet expired (current <
 * unlockCycle). These are exactly the stakers the contract holds a
 * current-cycle membership for, so `modelStakerSignerForCycle` resolves.
 */
export function isStakerInCurrentCycle(
  model: Readonly<Model>,
  address: string,
): boolean {
  const staker = model.stakers.get(address);
  if (!staker) return false;
  const cycle = currentRewardCycle(model);
  return staker.firstRewardCycle <= cycle && cycle < staker.unlockCycle;
}

/**
 * Mirrors the contract's `is-in-prepare-phase`: true when the current burn
 * height is within `prepareCycleLength` blocks of the next cycle's start.
 */
export function isInPreparePhase(model: Readonly<Model>): boolean {
  const cycle = currentRewardCycle(model);
  const nextCycleStart = rewardCycleToBurnHeight(model, cycle + 1n);
  return model.burnBlockHeight >= nextCycleStart - model.prepareCycleLength;
}

/**
 * The bond-index whose `setup-bond` window is open right now, or undefined.
 * Setup is allowed only in the BOND_GAP_CYCLES cycles before a bond starts,
 * and those windows are adjacent, so the eligible bond's start cycle is the
 * unique value in {current+1 … current+BOND_GAP_CYCLES} congruent to
 * `firstBondPeriodCycle` mod BOND_GAP_CYCLES. Bond N starts at
 * `firstBondPeriodCycle + N*BOND_GAP_CYCLES`.
 */
export function eligibleBondIndex(model: Readonly<Model>): bigint | undefined {
  const current = currentRewardCycle(model);
  const fbpc = model.firstBondPeriodCycle;
  for (
    let startCycle = current + 1n;
    startCycle <= current + BOND_GAP_CYCLES;
    startCycle++
  ) {
    if (startCycle >= fbpc && (startCycle - fbpc) % BOND_GAP_CYCLES === 0n) {
      return (startCycle - fbpc) / BOND_GAP_CYCLES;
    }
  }
  return undefined;
}

/** `model.bondAllowances` key: one entry per `protocol-bond-allowances` row. */
export function bondAllowanceKey(bondIndex: bigint, staker: string): string {
  return `${bondIndex}|${staker}`;
}

/** Reward cycle a bond's lock starts: `firstBondPeriodCycle + index * gap`. */
export function bondStartCycle(
  model: Readonly<Model>,
  bondIndex: bigint,
): bigint {
  return model.firstBondPeriodCycle + bondIndex * BOND_GAP_CYCLES;
}

/**
 * Bonds the staker can freshly register for now: set up, not yet started, with
 * a positive allowance, and the staker not already a member. Fresh-only (no
 * rollover), so a current member is excluded until their bond is unwound.
 */
export function registrableBondsForStaker(
  model: Readonly<Model>,
  staker: string,
): bigint[] {
  if (model.bondMemberships.has(staker)) return [];
  const result: bigint[] = [];
  for (const [bondIndex] of model.bonds) {
    const allowance = model.bondAllowances.get(
      bondAllowanceKey(bondIndex, staker),
    );
    if (allowance === undefined || allowance === 0n) continue;
    const startHeight = rewardCycleToBurnHeight(
      model,
      bondStartCycle(model, bondIndex),
    );
    if (model.burnBlockHeight < startHeight) result.push(bondIndex);
  }
  return result;
}

/**
 * Active bond registrations that would overlap a new bond registration for
 * `staker`. These target `register-for-bond`'s ERR_ALREADY_REGISTERED branch:
 * the new bond is set up and allowlisted, but its first cycle is before the
 * existing bond's end.
 */
export function overlappingBondTargetsForStaker(
  model: Readonly<Model>,
  staker: string,
): bigint[] {
  const membership = model.bondMemberships.get(staker);
  if (membership === undefined) return [];
  const existingEnd = bondEndCycle(model, membership.bondIndex);
  const result: bigint[] = [];
  for (const [bondIndex] of model.bonds) {
    const allowance = model.bondAllowances.get(
      bondAllowanceKey(bondIndex, staker),
    );
    if (allowance === undefined || allowance === 0n) continue;
    const startCycle = bondStartCycle(model, bondIndex);
    const startHeight = rewardCycleToBurnHeight(model, startCycle);
    if (model.burnBlockHeight < startHeight && startCycle < existingEnd) {
      result.push(bondIndex);
    }
  }
  return result;
}

/**
 * Set-up, allowlisted future bonds whose first cycle does not overlap the
 * staker's current bond membership. A call before the current bond's L1 unlock
 * height targets ERR_ROLLOVER_TOO_EARLY; after it, this is the bond-to-bond
 * rollover success surface.
 */
export function bondRolloverTargetsForStaker(
  model: Readonly<Model>,
  staker: string,
): bigint[] {
  const membership = model.bondMemberships.get(staker);
  if (membership === undefined) return [];
  const existingEnd = bondEndCycle(model, membership.bondIndex);
  const result: bigint[] = [];
  for (const [bondIndex] of model.bonds) {
    const allowance = model.bondAllowances.get(
      bondAllowanceKey(bondIndex, staker),
    );
    if (allowance === undefined || allowance === 0n) continue;
    const startCycle = bondStartCycle(model, bondIndex);
    const startHeight = rewardCycleToBurnHeight(model, startCycle);
    if (model.burnBlockHeight < startHeight && startCycle >= existingEnd) {
      result.push(bondIndex);
    }
  }
  return result;
}

/**
 * Set-up, allowlisted future bonds whose first cycle does not overlap the
 * staker's current STX-only lock. A successful register-for-bond call deletes
 * the staker-info row after adding the bond membership.
 */
export function stxRolloverBondTargetsForStaker(
  model: Readonly<Model>,
  staker: string,
): bigint[] {
  const stake = model.stakers.get(staker);
  if (stake === undefined) return [];
  if (model.bondMemberships.has(staker)) return [];
  const result: bigint[] = [];
  for (const [bondIndex] of model.bonds) {
    const allowance = model.bondAllowances.get(
      bondAllowanceKey(bondIndex, staker),
    );
    if (allowance === undefined || allowance === 0n) continue;
    const startCycle = bondStartCycle(model, bondIndex);
    const startHeight = rewardCycleToBurnHeight(model, startCycle);
    if (
      model.burnBlockHeight < startHeight &&
      stake.unlockCycle <= startCycle
    ) {
      result.push(bondIndex);
    }
  }
  return result;
}

/** First burn height when an existing bond can be rolled over. */
export function bondRolloverUnlockHeight(
  model: Readonly<Model>,
  bondIndex: bigint,
): bigint {
  return bondL1UnlockHeight(model, bondIndex);
}

/** Minimum L1 lockup unlock height accepted for a bond registration. */
export function bondL1UnlockHeight(
  model: Readonly<Model>,
  bondIndex: bigint,
): bigint {
  return (
    rewardCycleToBurnHeight(model, bondEndCycle(model, bondIndex)) -
    model.rewardCycleLength / 2n
  );
}

/**
 * Contract's `min-ustx-for-sats-amount`: the floor uSTX a staker must lock for
 * `sats`. Integer division at each step, matching the contract's truncation.
 */
export function minUstxForSats(
  sats: bigint,
  stxValueRatio: bigint,
  minUstxRatio: bigint,
): bigint {
  return (((stxValueRatio * sats) / 100n) * minUstxRatio) / 10000n;
}

/** Cycle a bond's lock ends (exclusive): `bondStartCycle + BOND_LENGTH_CYCLES`. */
export function bondEndCycle(
  model: Readonly<Model>,
  bondIndex: bigint,
): bigint {
  return bondStartCycle(model, bondIndex) + BOND_LENGTH_CYCLES;
}

/**
 * True while `get-bond-membership` still resolves for `staker`: a membership
 * exists and the current cycle is before the bond's end (the contract returns
 * none once the term is over).
 */
export function isActiveBondMember(
  model: Readonly<Model>,
  staker: string,
): boolean {
  const membership = model.bondMemberships.get(staker);
  if (membership === undefined) return false;
  return currentRewardCycle(model) < bondEndCycle(model, membership.bondIndex);
}

/** Stakers whose `get-bond-membership` still resolves (active term). */
export function activeBondMembers(model: Readonly<Model>): string[] {
  return [...model.bondMemberships.keys()].filter((s) =>
    isActiveBondMember(model, s),
  );
}

/**
 * Keep the model in lockstep with the chain. The contract silently expires a
 * staker at its unlock cycle, so prune them here to match.
 */
export function refreshModel(model: Model, real: Real) {
  model.burnBlockHeight = BigInt(real.network.burnBlockHeight);
  const cycle = currentRewardCycle(model);
  for (const [addr, staker] of model.stakers) {
    if (cycle >= staker.unlockCycle) {
      model.stakers.delete(addr);
    }
  }
}

export function logCommand({
  sender,
  action,
  value,
  error,
  bitcoinHeightBefore,
  stacksHeightBefore,
}: {
  sender?: string;
  action: string;
  value?: string | number | bigint;
  error?: string;
  bitcoinHeightBefore: number;
  stacksHeightBefore: number;
}) {
  const senderStr = (sender ?? 'system').padEnd(11, ' ');

  const items: string[] = [
    `₿ ${bitcoinHeightBefore}`,
    `Ӿ ${stacksHeightBefore}`,
    senderStr,
    action,
  ];
  if (value !== undefined) items.push(String(value));
  if (error !== undefined) items.push(`error ${error}`);

  const columnWidth = 65;
  const thinColumns = Math.floor(columnWidth / 5);
  // padEnd is a no-op once content >= width, which lets long actions (e.g.
  // `stake-err-invalid-num-cycles`) and uint128-range numbers run into the
  // next column. Reserve at least one trailing space so columns stay visually
  // distinct even when content overflows the nominal width.
  const prettyPrint = items.map((content, index) => {
    const width = index < 3 ? thinColumns : columnWidth;
    return content.padEnd(Math.max(width, content.length + 1));
  });
  prettyPrint.push('\n');

  process.stdout.write(prettyPrint.join(''));
}

export function trackCommandRun(model: Model, commandName: string) {
  const count = model.statistics.get(commandName) || 0;
  model.statistics.set(commandName, count + 1);
}

export function reportCommandRuns(model: Model) {
  console.log('\nCommand execution counts:');
  const orderedStatistics = Array.from(model.statistics.entries()).sort(
    ([keyA], [keyB]) => keyA.localeCompare(keyB),
  );

  logAsTree(orderedStatistics);
}

function logAsTree(statistics: [string, number][]) {
  const tree: { [key: string]: any } = {};

  statistics.forEach(([commandName, count]) => {
    const [root, ...restParts] = commandName.split('_');
    const rest = restParts.length > 0 ? restParts.join('_') : 'base';
    if (!tree[root]) tree[root] = {};
    tree[root][rest] = count;
  });

  const TEE = '├── ';
  const ELBOW = '└── ';
  const PIPE = '│   ';
  const GAP = '    ';

  const printNode = (node: any, indent: string) => {
    const keys = Object.keys(node).filter((k) => k !== 'base');
    keys.forEach((key, index) => {
      const isLast = index === keys.length - 1;
      const branch = isLast ? ELBOW : TEE;
      const childIndent = indent + (isLast ? GAP : PIPE);
      const value = node[key];
      if (typeof value === 'object') {
        const base = value['base'];
        const label = base !== undefined ? `${key}: ${base}` : key;
        console.log(`${indent}${branch}${label}`);
        printNode(value, childIndent);
      } else {
        console.log(`${indent}${branch}${key}: ${value}`);
      }
    });
  };

  printNode(tree, '');
}

export const getWalletNameByAddress = (address: string): string | undefined =>
  Object.entries(accounts).find(([, v]) => v.address === address)?.[0];

/**
 * Every signer-manager identifier a run can produce: the default `testSigner`
 * plus the `test-pox-5-signer-1..(MAX_SIGNERS-1)` instances DeploySigner
 * creates. A static candidate set for `fc.constantFrom`; Assert* commands gate
 * on `model.signers.has(...)` to pick only the registered ones.
 */
export const candidateSignerIds: string[] = [
  testSigner.identifier,
  ...Array.from(
    { length: MAX_SIGNERS - 1 },
    (_, i) => `${accounts.deployer.address}.test-pox-5-signer-${i + 1}`,
  ),
];

// Signer-key-grant (de)serialisation. The model stores grants as flat strings
// so they live in plain `Set`s; these are the only places that know the wire
// format. `|` is a safe delimiter: hex, principals, and decimal auth-ids never
// contain it.

/** `model.activeGrants` key: one entry per live `signer-key-grants` row. */
export function grantKey(signerKey: Uint8Array, signerManager: string): string {
  return `${hex.encode(signerKey)}|${signerManager}`;
}

/**
 * True when `signerManager`'s current key still has a live grant; the
 * condition every new-stake entry point re-checks (else
 * ERR_SIGNER_KEY_GRANT_NOT_FOUND). A revoked grant leaves the signer
 * registered but unstakeable.
 */
export function signerHasActiveGrant(
  model: Readonly<Model>,
  signerManager: string,
): boolean {
  const signer = model.signers.get(signerManager);
  if (!signer) return false;
  return model.activeGrants.has(grantKey(signer.signerKey, signerManager));
}

/**
 * Registered signers whose current key still has a live grant; the only
 * signers a new stake / stake-update can target.
 */
export function grantedSigners(model: Readonly<Model>): string[] {
  return [...model.signers.keys()].filter((s) =>
    signerHasActiveGrant(model, s),
  );
}

/**
 * Registered signers whose current key's grant has been revoked. A new stake
 * with them reverts `ERR_SIGNER_KEY_GRANT_NOT_FOUND`.
 */
export function revokedSigners(model: Readonly<Model>): string[] {
  return [...model.signers.keys()].filter(
    (s) => !signerHasActiveGrant(model, s),
  );
}

/** `model.usedGrants` key: one entry per `used-signer-key-grants` row. */
export function usedGrantKey(
  signerKey: Uint8Array,
  signerManager: string,
  authId: bigint,
): string {
  return `${hex.encode(signerKey)}|${signerManager}|${authId}`;
}

/** Inverse of `grantKey`. */
export function parseGrantKey(key: string): {
  signerKey: Uint8Array;
  signerManager: string;
} {
  const [signerKeyHex, signerManager] = key.split('|');
  return { signerKey: hex.decode(signerKeyHex), signerManager };
}

/** Inverse of `usedGrantKey`. */
export function parseUsedGrantKey(key: string): {
  signerKey: Uint8Array;
  signerManager: string;
  authId: bigint;
} {
  const [signerKeyHex, signerManager, authId] = key.split('|');
  return {
    signerKey: hex.decode(signerKeyHex),
    signerManager,
    authId: BigInt(authId),
  };
}

// Per-cycle key encoders for the model's mirror maps. The contract keys these
// maps by composite tuples; flatten to the same `|`-joined strings so they
// live in plain `Map`s.

function signerCycleKey(signer: string, cycle: bigint): string {
  return `${signer}|${cycle}`;
}

function stakerCycleKey(staker: string, cycle: bigint): string {
  return `${staker}|${cycle}`;
}

function stakerSignerCycleKey(
  staker: string,
  signer: string,
  cycle: bigint,
): string {
  return `${staker}|${signer}|${cycle}`;
}

function modelAddSignerToSetForCycle(
  model: Model,
  signer: string,
  cycle: bigint,
): void {
  const key = signerCycleKey(signer, cycle);
  const last = model.signerSetLastPerCycle.get(cycle);
  if (last !== undefined) {
    const lastKey = signerCycleKey(last, cycle);
    const lastNode = model.signerSetItemsPerCycle.get(lastKey)!;
    model.signerSetItemsPerCycle.set(lastKey, {
      prev: lastNode.prev,
      next: signer,
    });
    model.signerSetItemsPerCycle.set(key, { prev: last, next: null });
  } else {
    model.signerSetItemsPerCycle.set(key, { prev: null, next: null });
    model.signerSetFirstPerCycle.set(cycle, signer);
  }
  model.signerSetLastPerCycle.set(cycle, signer);
}

function modelRemoveSignerFromSetForCycle(
  model: Model,
  signer: string,
  cycle: bigint,
): void {
  const key = signerCycleKey(signer, cycle);
  const node = model.signerSetItemsPerCycle.get(key)!;
  if (node.prev !== null) {
    const prevKey = signerCycleKey(node.prev, cycle);
    const prevNode = model.signerSetItemsPerCycle.get(prevKey)!;
    model.signerSetItemsPerCycle.set(prevKey, {
      prev: prevNode.prev,
      next: node.next,
    });
  } else if (node.next !== null) {
    model.signerSetFirstPerCycle.set(cycle, node.next);
  } else {
    model.signerSetFirstPerCycle.delete(cycle);
    model.signerSetLastPerCycle.delete(cycle);
  }

  if (node.next !== null) {
    const nextKey = signerCycleKey(node.next, cycle);
    const nextNode = model.signerSetItemsPerCycle.get(nextKey)!;
    model.signerSetItemsPerCycle.set(nextKey, {
      prev: node.prev,
      next: nextNode.next,
    });
  } else if (node.prev !== null) {
    model.signerSetLastPerCycle.set(cycle, node.prev);
  }

  model.signerSetItemsPerCycle.delete(key);
}

// Bond (some bond-index) variant key encoders. Lead with cycle then bondIndex
// so the prefix matches the contract's tuple ordering for these maps.

function bondTotalCycleKey(cycle: bigint, bondIndex: bigint): string {
  return `${cycle}|${bondIndex}`;
}

function bondSignerCycleKey(
  cycle: bigint,
  bondIndex: bigint,
  signer: string,
): string {
  return `${cycle}|${bondIndex}|${signer}`;
}

function bondStakerCycleKey(
  cycle: bigint,
  bondIndex: bigint,
  signer: string,
  staker: string,
): string {
  return `${cycle}|${bondIndex}|${signer}|${staker}`;
}

// Per-cycle model writes mirroring the contract's `add-staker-to-signer-for-
// cycle` / `remove-staker-from-signer-for-cycle` folds, for the four
// unconditional-write maps only (the threshold-gated `signer-shares` /
// `total-shares` maps are not modelled). Call them in the Act's "Update model"
// step so each touched cycle holds exactly what the contract committed.

/**
 * Mirror of `add-staker-to-signer-cycles`: add `staker`/`signer`/`amountUstx`
 * across `[firstCycle, firstCycle + numCycles)`. Bonds pass `isStxStaking`
 * false, so the stx-only staker-shares stay 0 (the contract's `stake-amount`).
 */
export function modelAddStakerToCycles(
  model: Model,
  staker: string,
  signer: string,
  firstCycle: bigint,
  numCycles: bigint,
  amountUstx: bigint,
  isStxStaking = true,
): void {
  for (let i = 0n; i < numCycles; i++) {
    const cycle = firstCycle + i;
    const sdKey = signerCycleKey(signer, cycle);
    const curDelegated = model.signerDelegatedPerCycle.get(sdKey) ?? 0n;
    const newDelegated = curDelegated + amountUstx;
    if (
      curDelegated < SIGNER_SET_MIN_USTX &&
      newDelegated >= SIGNER_SET_MIN_USTX
    ) {
      modelAddSignerToSetForCycle(model, signer, cycle);
    }
    model.stakerSignerCycleMemberships.set(stakerCycleKey(staker, cycle), {
      amountUstx,
      signer,
    });
    model.signerDelegatedPerCycle.set(sdKey, newDelegated);
    // Pending stx stake accrues unconditionally; the none-variant shares mirror
    // it only while the signer's delegation is over SIGNER_SET_MIN_USTX.
    model.signerPendingStakedPerCycle.set(
      sdKey,
      (model.signerPendingStakedPerCycle.get(sdKey) ?? 0n) +
        (isStxStaking ? amountUstx : 0n),
    );
    model.stakerSharesStakedForCycle.set(
      stakerSignerCycleKey(staker, signer, cycle),
      isStxStaking ? amountUstx : 0n,
    );
    model.ustxDelegatedPerCycle.set(
      cycle,
      (model.ustxDelegatedPerCycle.get(cycle) ?? 0n) + amountUstx,
    );
  }
}

/**
 * Mirror of `remove-staker-from-cycles`: remove `staker` across
 * `[firstCycle, firstCycle + numCycles)`. Like the contract, the amount and
 * signer subtracted come from the stored per-cycle membership (what was live
 * when that cycle was written), not from the staker's current record. That's
 * why a StakeUpdate that changes the amount still decrements each cycle by
 * what was actually added there. Bonds pass `isStxStaking` false, so the
 * pending stx stake is left untouched.
 */
export function modelRemoveStakerFromCycles(
  model: Model,
  staker: string,
  firstCycle: bigint,
  numCycles: bigint,
  isStxStaking = true,
): void {
  for (let i = 0n; i < numCycles; i++) {
    const cycle = firstCycle + i;
    const memKey = stakerCycleKey(staker, cycle);
    // Contract does `(unwrap! ... ERR_NOT_STAKING)`: a membership must exist
    // for every cycle in a removed range. A miss is a model bug, so let the
    // destructure throw rather than silently skipping.
    const membership = model.stakerSignerCycleMemberships.get(memKey)!;
    const { amountUstx, signer } = membership;
    model.stakerSignerCycleMemberships.delete(memKey);
    const sdKey = signerCycleKey(signer, cycle);
    const curDelegated = model.signerDelegatedPerCycle.get(sdKey) ?? 0n;
    const newDelegated = curDelegated - amountUstx;
    if (
      model.signerSetItemsPerCycle.has(sdKey) &&
      newDelegated < SIGNER_SET_MIN_USTX
    ) {
      modelRemoveSignerFromSetForCycle(model, signer, cycle);
    }
    model.signerDelegatedPerCycle.set(sdKey, newDelegated);
    model.signerPendingStakedPerCycle.set(
      sdKey,
      (model.signerPendingStakedPerCycle.get(sdKey) ?? 0n) -
        (isStxStaking ? amountUstx : 0n),
    );
    model.stakerSharesStakedForCycle.delete(
      stakerSignerCycleKey(staker, signer, cycle),
    );
    model.ustxDelegatedPerCycle.set(
      cycle,
      (model.ustxDelegatedPerCycle.get(cycle) ?? 0n) - amountUstx,
    );
  }
}

// Bond per-cycle model writes mirroring `add-staker-to-bond-for-cycle` /
// `remove-staker-from-bond-for-cycle`. Unlike the none variant these always
// move (no threshold gate), so they are fully derivable. Call them in the
// Act's "Update model" step so each touched cycle holds what the contract
// committed. staker-shares is an absolute set (not a delta).

/**
 * Mirror of `add-staker-to-bond-cycles`: across `[firstCycle, firstCycle +
 * numCycles)`, `total += amountSats`, `signer += amountSats`, and the staker's
 * shares are set absolute to `amountSats`.
 */
export function modelAddStakerToBondCycles(
  model: Model,
  staker: string,
  signer: string,
  bondIndex: bigint,
  firstCycle: bigint,
  numCycles: bigint,
  amountSats: bigint,
): void {
  for (let i = 0n; i < numCycles; i++) {
    const cycle = firstCycle + i;
    const totalKey = bondTotalCycleKey(cycle, bondIndex);
    model.bondTotalSharesForCycle.set(
      totalKey,
      (model.bondTotalSharesForCycle.get(totalKey) ?? 0n) + amountSats,
    );
    const signerKey = bondSignerCycleKey(cycle, bondIndex, signer);
    model.bondSignerSharesForCycle.set(
      signerKey,
      (model.bondSignerSharesForCycle.get(signerKey) ?? 0n) + amountSats,
    );
    // Absolute set, matching the contract's `(map-set ... amount-sats)`.
    model.bondStakerSharesForCycle.set(
      bondStakerCycleKey(cycle, bondIndex, signer, staker),
      amountSats,
    );
  }
}

/**
 * Mirror of `remove-staker-from-bond-cycles`: across `[firstCycle, firstCycle +
 * numCycles)`, `total -= amountSats`, `signer -= amountSats`, and the staker's
 * shares are set to `0n` (the contract sets `u0`, it does not delete the row).
 */
export function modelRemoveStakerFromBondCycles(
  model: Model,
  staker: string,
  signer: string,
  bondIndex: bigint,
  firstCycle: bigint,
  numCycles: bigint,
  amountSats: bigint,
): void {
  for (let i = 0n; i < numCycles; i++) {
    const cycle = firstCycle + i;
    const totalKey = bondTotalCycleKey(cycle, bondIndex);
    model.bondTotalSharesForCycle.set(
      totalKey,
      (model.bondTotalSharesForCycle.get(totalKey) ?? 0n) - amountSats,
    );
    const signerKey = bondSignerCycleKey(cycle, bondIndex, signer);
    model.bondSignerSharesForCycle.set(
      signerKey,
      (model.bondSignerSharesForCycle.get(signerKey) ?? 0n) - amountSats,
    );
    // Set to zero, not deleted, matching the contract's `(map-set ... u0)`.
    model.bondStakerSharesForCycle.set(
      bondStakerCycleKey(cycle, bondIndex, signer, staker),
      0n,
    );
  }
}

/**
 * Mirror of `unstake-sats-from-bond-cycles`: for each affected cycle, derive
 * the signer from the staker's per-cycle membership, subtract only the
 * withdrawal from aggregate shares, and set the staker's bond shares to the new
 * remaining sats.
 */
export function modelUnstakeSatsFromBondCycles(
  model: Model,
  staker: string,
  bondIndex: bigint,
  firstCycle: bigint,
  numCycles: bigint,
  amountToWithdrawalSats: bigint,
  newAmountSats: bigint,
): void {
  for (let i = 0n; i < numCycles; i++) {
    const cycle = firstCycle + i;
    const signer = modelStakerSignerForCycle(model, staker, cycle);
    if (signer === undefined) {
      throw new Error(
        `Missing signer-cycle membership for ${staker} at cycle ${cycle}`,
      );
    }

    const totalKey = bondTotalCycleKey(cycle, bondIndex);
    model.bondTotalSharesForCycle.set(
      totalKey,
      (model.bondTotalSharesForCycle.get(totalKey) ?? 0n) -
        amountToWithdrawalSats,
    );

    const signerKey = bondSignerCycleKey(cycle, bondIndex, signer);
    model.bondSignerSharesForCycle.set(
      signerKey,
      (model.bondSignerSharesForCycle.get(signerKey) ?? 0n) -
        amountToWithdrawalSats,
    );

    model.bondStakerSharesForCycle.set(
      bondStakerCycleKey(cycle, bondIndex, signer, staker),
      newAmountSats,
    );
  }
}

/**
 * The signer the model recorded for `staker` at `cycle` (its per-cycle
 * membership signer, which a mid-lock signer change can make differ from the
 * staker's latest `signer`). Undefined when the staker has no membership that
 * cycle.
 */
export function modelStakerSignerForCycle(
  model: Readonly<Model>,
  staker: string,
  cycle: bigint,
): string | undefined {
  return model.stakerSignerCycleMemberships.get(stakerCycleKey(staker, cycle))
    ?.signer;
}

// Per-cycle invariant checks. Each asserts one unconditional-write contract
// read against the model's mirror map for that exact cycle (default 0/null
// when absent, matching the contract getters' `default-to`).

export function assertSignerDelegationForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  signer: string,
): void {
  expect(
    rov(real.contracts.pox5.getAmountDelegatedForSigner(signer, cycle)),
  ).toBe(
    model.signerDelegatedPerCycle.get(signerCycleKey(signer, cycle)) ?? 0n,
  );
}

export function assertStakerSharesForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  staker: string,
  signer: string,
): void {
  expect(
    rov(
      real.contracts.pox5.getStakerSharesStakedForCycle(
        staker,
        cycle,
        null,
        signer,
      ),
    ),
  ).toBe(
    model.stakerSharesStakedForCycle.get(
      stakerSignerCycleKey(staker, signer, cycle),
    ) ?? 0n,
  );
}

// Bond (some bond-index) variant per-cycle asserts. Each reads one getter
// with the real bondIndex (the stx-only `assertStakerSharesForCycle` passes
// null) and compares to the model map, defaulting 0n when absent to match the
// contract getters' `default-to u0`.

export function assertBondTotalSharesForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  bondIndex: bigint,
): void {
  expect(
    rov(real.contracts.pox5.getTotalSharesStakedForCycle(cycle, bondIndex)),
  ).toBe(
    model.bondTotalSharesForCycle.get(bondTotalCycleKey(cycle, bondIndex)) ??
      0n,
  );
}

export function assertBondSignerSharesForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  bondIndex: bigint,
  signer: string,
): void {
  expect(
    rov(
      real.contracts.pox5.getSignerSharesStakedForCycle(
        signer,
        cycle,
        bondIndex,
      ),
    ),
  ).toBe(
    model.bondSignerSharesForCycle.get(
      bondSignerCycleKey(cycle, bondIndex, signer),
    ) ?? 0n,
  );
}

export function assertBondStakerSharesForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  bondIndex: bigint,
  signer: string,
  staker: string,
): void {
  expect(
    rov(
      real.contracts.pox5.getStakerSharesStakedForCycle(
        staker,
        cycle,
        bondIndex,
        signer,
      ),
    ),
  ).toBe(
    model.bondStakerSharesForCycle.get(
      bondStakerCycleKey(cycle, bondIndex, signer, staker),
    ) ?? 0n,
  );
}

export function assertSignerCycleMembership(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  staker: string,
): void {
  expect(
    rov(real.contracts.pox5.getSignerCycleMembership(staker, cycle)),
  ).toEqual(
    model.stakerSignerCycleMemberships.get(stakerCycleKey(staker, cycle)) ??
      null,
  );
}

export function assertTotalDelegatedForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
): void {
  expect(rov(real.contracts.pox5.getUstxDelegatedForCycle(cycle))).toBe(
    model.ustxDelegatedPerCycle.get(cycle) ?? 0n,
  );
}

// None-variant (stx-only) share reads, which are threshold-gated. The contract
// writes a signer's shares only while its delegation is over
// SIGNER_SET_MIN_USTX, but `signerPendingStakedPerCycle` accrues regardless,
// so the live value is "pending if over the threshold, else 0".

/** The signer's pending stx stake, the unconditional running sum. */
export function modelSignerPending(
  model: Readonly<Model>,
  signer: string,
  cycle: bigint,
): bigint {
  return (
    model.signerPendingStakedPerCycle.get(signerCycleKey(signer, cycle)) ?? 0n
  );
}

/**
 * Contract's none-variant `signer-shares-staked-for-cycle`: the signer's
 * pending stake while its delegation is over the threshold, else 0.
 */
export function modelSignerSharesNone(
  model: Readonly<Model>,
  signer: string,
  cycle: bigint,
): bigint {
  const delegated =
    model.signerDelegatedPerCycle.get(signerCycleKey(signer, cycle)) ?? 0n;
  return delegated >= SIGNER_SET_MIN_USTX
    ? modelSignerPending(model, signer, cycle)
    : 0n;
}

/**
 * Contract's none-variant `total-shares-staked-for-cycle`: the summed pending
 * stake of every signer over the threshold this cycle.
 */
export function modelTotalSharesNone(
  model: Readonly<Model>,
  cycle: bigint,
): bigint {
  let total = 0n;
  for (const [key, delegated] of model.signerDelegatedPerCycle) {
    if (delegated < SIGNER_SET_MIN_USTX) continue;
    if (BigInt(key.slice(key.lastIndexOf('|') + 1)) === cycle) {
      total += model.signerPendingStakedPerCycle.get(key) ?? 0n;
    }
  }
  return total;
}

export function modelSignerSetItemForCycle(
  model: Readonly<Model>,
  signer: string,
  cycle: bigint,
): { prev: string | null; next: string | null } | null {
  return (
    model.signerSetItemsPerCycle.get(signerCycleKey(signer, cycle)) ?? null
  );
}

export function assertCurrentPoxRewardCycle(
  model: Readonly<Model>,
  real: Real,
): void {
  expect(rov(real.contracts.pox5.currentPoxRewardCycle())).toBe(
    currentRewardCycle(model),
  );
}

export function assertPoxInfo(model: Readonly<Model>, real: Real): void {
  expect(rovOk(real.contracts.pox5.getPoxInfo())).toEqual({
    firstBurnchainBlockHeight: model.firstBurnHeight,
    minAmountUstx: SIGNER_SET_MIN_USTX,
    prepareCycleLength: model.prepareCycleLength,
    rewardCycleId: currentRewardCycle(model),
    rewardCycleLength: model.rewardCycleLength,
    totalLiquidSupplyUstx: model.totalLiquidSupplyUstx,
  });
}

export function assertSignerSetItemForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  signer: string,
): void {
  expect(
    rov(real.contracts.pox5.getSignerSetItemForCycle({ cycle, signer })),
  ).toEqual(modelSignerSetItemForCycle(model, signer, cycle));
}

export function assertSignerSetFirstForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
): void {
  expect(rov(real.contracts.pox5.getSignerSetFirstItemForCycle(cycle))).toBe(
    model.signerSetFirstPerCycle.get(cycle) ?? null,
  );
}

export function assertSignerSetLastForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
): void {
  expect(rov(real.contracts.pox5.getSignerSetLastItemForCycle(cycle))).toBe(
    model.signerSetLastPerCycle.get(cycle) ?? null,
  );
}

export function assertSignerPendingForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  signer: string,
): void {
  expect(
    rov(real.contracts.pox5.getSignerPendingStakedUstxPerCycle(signer, cycle)),
  ).toBe(modelSignerPending(model, signer, cycle));
}

export function assertSignerSharesNoneForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  signer: string,
): void {
  expect(
    rov(real.contracts.pox5.getSignerSharesStakedForCycle(signer, cycle, null)),
  ).toBe(modelSignerSharesNone(model, signer, cycle));
}

export function assertTotalSharesNoneForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
): void {
  expect(
    rov(real.contracts.pox5.getTotalSharesStakedForCycle(cycle, null)),
  ).toBe(modelTotalSharesNone(model, cycle));
}

/**
 * Contract `get-rewards`: the contract's sBTC balance net of staked sats and
 * the reserve, i.e. the sBTC available to distribute as rewards.
 */
export function modelGetRewards(model: Readonly<Model>): bigint {
  return (
    model.contractSbtcBalance - model.totalSbtcStaked - model.reserveBalance
  );
}

/** Contract `get-new-rewards`: rewards arrived since the last computation. */
export function modelGetNewRewards(model: Readonly<Model>): bigint {
  return modelGetRewards(model) - model.lastAccountedRewardsOnly;
}

/**
 * A principal's live sBTC balance matches the model's ledger mirror. Works for
 * wallets (seeded at genesis), signer managers (credited by claims), and any
 * principal the model never touched (defaults to 0).
 */
export function assertSbtcBalance(
  model: Readonly<Model>,
  address: string,
): void {
  expect(sbtcBalance(address)).toBe(model.sbtcBalances.get(address) ?? 0n);
}

/**
 * The contract principal's live sBTC balance matches `contractSbtcBalance`.
 * This is the balance `get-rewards` derives from, so a drift here means the
 * staked-sats, reserve, and reward-pool accounting has diverged.
 */
export function assertContractSbtcBalance(model: Readonly<Model>): void {
  expect(sbtcBalance(POX5_BOOT_ID)).toBe(model.contractSbtcBalance);
}

/** `rewardsPerTokenForCycle` key: the none pool uses `n`, bonds their index. */
export function rptKey(cycle: bigint, bondIndex: bigint | null): string {
  return `${cycle}|${bondIndex ?? 'n'}`;
}

/**
 * `calculate-rewards` snapshot height: the last burn height of the prior
 * distribution (half) cycle. Reruns within one half-cycle find this unmoved
 * and abort, so it gates how often a distribution can run.
 */
export function rewardsCalculationHeight(model: Readonly<Model>): bigint {
  const halfCycle = model.rewardCycleLength / 2n;
  const distributionCycle =
    (model.burnBlockHeight - model.firstBurnHeight) / halfCycle;
  return model.firstBurnHeight + distributionCycle * halfCycle - 1n;
}

/** Bond indices active at `height`: set up, and `height` in (start, end]. */
export function activeBondsAtHeight(
  model: Readonly<Model>,
  height: bigint,
): bigint[] {
  const result: bigint[] = [];
  for (const [bondIndex] of model.bonds) {
    const startHeight = rewardCycleToBurnHeight(
      model,
      bondStartCycle(model, bondIndex),
    );
    const endHeight = rewardCycleToBurnHeight(
      model,
      bondEndCycle(model, bondIndex),
    );
    if (height > startHeight && height <= endHeight) result.push(bondIndex);
  }
  return result;
}

/**
 * Sort bonds the way the reward fold demands: stx-value-ratio descending, bond
 * index ascending as the tie-breaker. Used both for the correct order and to
 * place a deliberately-wrong bond in the error-path commands.
 */
export function sortBondsForRewards(
  model: Readonly<Model>,
  bonds: bigint[],
): bigint[] {
  return [...bonds].sort((a, b) => {
    const ra = model.bonds.get(a)!.stxValueRatio;
    const rb = model.bonds.get(b)!.stxValueRatio;
    if (ra !== rb) return ra > rb ? -1 : 1;
    return a < b ? -1 : 1;
  });
}

/** Active bonds in the order `calculate-rewards` demands. */
export function sortedActiveBonds(
  model: Readonly<Model>,
  height: bigint,
): bigint[] {
  return sortBondsForRewards(model, activeBondsAtHeight(model, height));
}

/** Reward cycle whose stakers a `calculate-rewards` distribution credits. */
export function rewardsStxCycle(model: Readonly<Model>): bigint {
  return (
    (rewardsCalculationHeight(model) - model.firstBurnHeight) /
    model.rewardCycleLength
  );
}

/** One bond's slice of a `calculate-rewards` distribution. */
export interface BondDistribution {
  bondIndex: bigint;
  accruedRewardsPerSat: bigint;
  cumulativeRewardsPerSat: bigint;
}

/** The full predicted outcome of one `calculate-rewards` call. */
export interface CalcRewardsResult {
  calculationHeight: bigint;
  stxCycle: bigint;
  bondPeriods: bigint[];
  grossAccruedRewards: bigint;
  bondDistributions: BondDistribution[];
  totalBondRewards: bigint;
  reserveDeposit: bigint;
  newReserveBalance: bigint;
  stxStakerRewards: bigint;
  cycleStakedUstx: bigint;
  accruedRewardsPerUstx: bigint;
  cumulativeRewardsPerUstx: bigint;
  newLastAccounted: bigint;
}

/**
 * Predict a `calculate-rewards` call from current model state, without
 * mutating. Each active bond earns its target yield (capped by what is left)
 * in (ratio desc, index asc) order. The reserve skims its cut from the
 * remainder, and the rest spreads across stx stakers through the none-pool
 * accumulator. With no stx staked this cycle, the whole staker cut folds into
 * the reserve instead.
 */
export function modelCalculateRewards(
  model: Readonly<Model>,
): CalcRewardsResult {
  const calculationHeight = rewardsCalculationHeight(model);
  const stxCycle = rewardsStxCycle(model);
  const grossAccruedRewards = modelGetNewRewards(model);
  const bondPeriods = sortedActiveBonds(model, calculationHeight);

  let available = grossAccruedRewards;
  const bondDistributions: BondDistribution[] = [];
  for (const bondIndex of bondPeriods) {
    const { targetRate } = model.bonds.get(bondIndex)!;
    const totalSats =
      model.bondTotalSharesForCycle.get(
        bondTotalCycleKey(stxCycle, bondIndex),
      ) ?? 0n;
    const targetYield = (totalSats * targetRate) / 10000n / 50n;
    const earned = available >= targetYield ? targetYield : available;
    const accruedRewardsPerSat =
      totalSats === 0n ? 0n : (earned * PRECISION) / totalSats;
    const current =
      model.rewardsPerTokenForCycle.get(rptKey(stxCycle, bondIndex)) ?? 0n;
    bondDistributions.push({
      bondIndex,
      accruedRewardsPerSat,
      cumulativeRewardsPerSat: current + accruedRewardsPerSat,
    });
    available -= earned;
  }
  const totalBondRewards = grossAccruedRewards - available;

  const reserveCut = (available * RESERVE_RATIO) / 10000n;
  const stxStakerRewards = available - reserveCut;
  const cycleStakedUstx = modelTotalSharesNone(model, stxCycle);
  const noStxStakers = cycleStakedUstx === 0n;
  const accruedRewardsPerUstx = noStxStakers
    ? 0n
    : (stxStakerRewards * PRECISION) / cycleStakedUstx;
  const currentNone =
    model.rewardsPerTokenForCycle.get(rptKey(stxCycle, null)) ?? 0n;
  const cumulativeRewardsPerUstx = currentNone + accruedRewardsPerUstx;
  const unallocatedStakerCut = noStxStakers ? stxStakerRewards : 0n;
  const reserveDeposit = reserveCut + unallocatedStakerCut;

  return {
    calculationHeight,
    stxCycle,
    bondPeriods,
    grossAccruedRewards,
    bondDistributions,
    totalBondRewards,
    reserveDeposit,
    newReserveBalance: model.reserveBalance + reserveDeposit,
    stxStakerRewards,
    cycleStakedUstx,
    accruedRewardsPerUstx,
    cumulativeRewardsPerUstx,
    newLastAccounted:
      model.lastAccountedRewardsOnly + (grossAccruedRewards - reserveDeposit),
  };
}

export function assertRewardsPerTokenForCycle(
  model: Readonly<Model>,
  real: Real,
  cycle: bigint,
  bondIndex: bigint | null,
): void {
  expect(
    rov(real.contracts.pox5.getRewardsPerTokenForCycle(cycle, bondIndex)),
  ).toBe(model.rewardsPerTokenForCycle.get(rptKey(cycle, bondIndex)) ?? 0n);
}

/** `signerRewards*` map key: cycle, bond (none is `n`), and the signer. */
export function signerRewardKey(
  cycle: bigint,
  bondIndex: bigint | null,
  signer: string,
): string {
  return `${cycle}|${bondIndex ?? 'n'}|${signer}`;
}

/** A signer's shares feeding the reward pool at `cycle`: none pool or one bond. */
export function modelSignerSharesForRewards(
  model: Readonly<Model>,
  signer: string,
  cycle: bigint,
  bondIndex: bigint | null,
): bigint {
  return bondIndex === null
    ? modelSignerSharesNone(model, signer, cycle)
    : (model.bondSignerSharesForCycle.get(
        bondSignerCycleKey(cycle, bondIndex, signer),
      ) ?? 0n);
}

/**
 * Contract `get-earned`: the signer's rewards owed since its last settle,
 * `unclaimed + shares*(rpt - rptSettled)/PRECISION`. The accumulator only
 * grows, so the difference never goes negative.
 */
export function modelEarnedSigner(
  model: Readonly<Model>,
  signer: string,
  cycle: bigint,
  bondIndex: bigint | null,
): bigint {
  const key = signerRewardKey(cycle, bondIndex, signer);
  const shares = modelSignerSharesForRewards(model, signer, cycle, bondIndex);
  const rpt = model.rewardsPerTokenForCycle.get(rptKey(cycle, bondIndex)) ?? 0n;
  const rptSettled = model.signerRewardsPerTokenSettled.get(key) ?? 0n;
  const unclaimed = model.signerUnclaimedRewards.get(key) ?? 0n;
  return unclaimed + (shares * (rpt - rptSettled)) / PRECISION;
}

/**
 * Every (signer, cycle) with a positive none-pool balance to claim, bounded by
 * the deployed signers times the cycles a distribution has credited.
 */
export function claimableNonePool(
  model: Readonly<Model>,
): { signer: string; cycle: bigint; earned: bigint }[] {
  const cycles = new Set<bigint>();
  for (const mapKey of model.rewardsPerTokenForCycle.keys()) {
    const [cycleStr, bond] = mapKey.split('|');
    if (bond === 'n') cycles.add(BigInt(cycleStr));
  }
  const result: { signer: string; cycle: bigint; earned: bigint }[] = [];
  for (const signer of model.deployedSigners) {
    for (const cycle of cycles) {
      const earned = modelEarnedSigner(model, signer, cycle, null);
      if (earned > 0n) result.push({ signer, cycle, earned });
    }
  }
  return result;
}

/** `stakerRewards*` map key: cycle, bond (none is `n`), signer, and staker. */
export function stakerRewardKey(
  cycle: bigint,
  bondIndex: bigint | null,
  signer: string,
  staker: string,
): string {
  return `${cycle}|${bondIndex ?? 'n'}|${signer}|${staker}`;
}

/**
 * Contract `get-earned-staker-rewards`: a staker's owed rewards since its last
 * settle, earned against the signer's frozen snapshot,
 * `unclaimed + shares*(signerRpt - settled)/PRECISION`.
 */
export function modelEarnedStaker(
  model: Readonly<Model>,
  signer: string,
  cycle: bigint,
  bondIndex: bigint | null,
  staker: string,
): bigint {
  const key = stakerRewardKey(cycle, bondIndex, signer, staker);
  const shares =
    bondIndex === null
      ? (model.stakerSharesStakedForCycle.get(
          stakerSignerCycleKey(staker, signer, cycle),
        ) ?? 0n)
      : (model.bondStakerSharesForCycle.get(
          bondStakerCycleKey(cycle, bondIndex, signer, staker),
        ) ?? 0n);
  const signerRpt =
    model.signerRewardsPerTokenForCycle.get(
      signerRewardKey(cycle, bondIndex, signer),
    ) ?? 0n;
  const settled = model.stakerRewardsPerTokenSettled.get(key) ?? 0n;
  const unclaimed = model.stakerUnclaimedRewards.get(key) ?? 0n;
  return unclaimed + (shares * (signerRpt - settled)) / PRECISION;
}

/**
 * Every (signer, cycle, staker) with a positive none-pool balance to claim:
 * the signer has settled the cycle and still holds the sBTC to pay the staker.
 */
export function claimableStakerNone(
  model: Readonly<Model>,
): { signer: string; cycle: bigint; staker: string; earned: bigint }[] {
  const result: {
    signer: string;
    cycle: bigint;
    staker: string;
    earned: bigint;
  }[] = [];
  for (const mapKey of model.signerRewardsPerTokenForCycle.keys()) {
    const [cycleStr, bond, signer] = mapKey.split('|');
    if (bond !== 'n') continue;
    const cycle = BigInt(cycleStr);
    for (const [staker] of model.stakers) {
      const earned = modelEarnedStaker(model, signer, cycle, null, staker);
      if (earned > 0n && (model.sbtcBalances.get(signer) ?? 0n) >= earned) {
        result.push({ signer, cycle, staker, earned });
      }
    }
  }
  return result;
}

// Per-principal identity invariants (not cycle-scoped): the contract's staker
// and signer records must match the model for any principal. The null-or-value
// branch lives inside the pure derivation, so the assertion stays a single
// flat `toEqual`, never a conditional choosing the expected value inline.

/** Contract-shaped `get-staker-info` value the model predicts for `staker`. */
export function modelStakerInfo(
  stakers: Map<string, StakerState>,
  staker: string,
): {
  amountUstx: bigint;
  firstRewardCycle: bigint;
  numCycles: bigint;
  signer: string;
} | null {
  const st = stakers.get(staker);
  if (!st) return null;
  return {
    amountUstx: st.amountUstx,
    firstRewardCycle: st.firstRewardCycle,
    numCycles: st.numCycles,
    signer: st.signer,
  };
}

export function assertStakerInfo(
  stakers: Map<string, StakerState>,
  real: Real,
  staker: string,
): void {
  expect(rov(real.contracts.pox5.getStakerInfo(staker))).toEqual(
    modelStakerInfo(stakers, staker),
  );
}

export function assertSignerInfo(
  signers: Map<string, { signerKey: Uint8Array }>,
  real: Real,
  signer: string,
): void {
  expect(rov(real.contracts.pox5.getSignerInfo(signer))).toEqual(
    signers.get(signer)?.signerKey ?? null,
  );
}

// Locked-STX invariant. clarinet-sdk applies the pox-5 STX lock in simnet
// only for the boot pox-5, so the runtime `stx-account` of an active staker
// must agree with the model.

/** Read a principal's `stx-account` (locked / unlocked / unlock-height). */
export function stxAccount(
  real: Real,
  address: string,
): { locked: bigint; unlockHeight: bigint; unlocked: bigint } {
  const acct = cvToValue(
    hexToCV(real.network.runSnippet(`(stx-account '${address})`)),
  );
  return {
    locked: BigInt(acct.locked.value),
    unlockHeight: BigInt(acct['unlock-height'].value),
    unlocked: BigInt(acct.unlocked.value),
  };
}

/**
 * An active staker's locked balance must equal `amountUstx`, unlocking at
 * `unlockBurnHeight`.
 */
export function assertStakerLock(
  model: Readonly<Model>,
  real: Real,
  staker: string,
): void {
  const st = model.stakers.get(staker);
  expect(st).toBeDefined();
  const acct = stxAccount(real, staker);
  expect(acct.locked).toBe(st!.amountUstx);
  expect(acct.unlockHeight).toBe(st!.unlockBurnHeight);
}
