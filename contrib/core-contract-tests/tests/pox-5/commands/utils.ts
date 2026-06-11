import type { Model, Real, StakerState } from './types';
import { accounts } from '../../clarigen-types';
import {
  BOND_GAP_CYCLES,
  BOND_LENGTH_CYCLES,
  MAX_SIGNERS,
  testSigner,
} from '../pox-5-helpers';
import { rov } from '@clarigen/test';
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

  const columnWidth = 30;
  const halfColumns = Math.floor(columnWidth / 2);
  // padEnd is a no-op once content >= width, which lets long actions (e.g.
  // `stake-err-invalid-num-cycles`) and uint128-range numbers run into the
  // next column. Reserve at least one trailing space so columns stay visually
  // distinct even when content overflows the nominal width.
  const prettyPrint = items.map((content, index) => {
    const width = index < 3 ? halfColumns : columnWidth;
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
    model.stakerSignerCycleMemberships.set(stakerCycleKey(staker, cycle), {
      amountUstx,
      signer,
    });
    const sdKey = signerCycleKey(signer, cycle);
    model.signerDelegatedPerCycle.set(
      sdKey,
      (model.signerDelegatedPerCycle.get(sdKey) ?? 0n) + amountUstx,
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
 * what was actually added there.
 */
export function modelRemoveStakerFromCycles(
  model: Model,
  staker: string,
  firstCycle: bigint,
  numCycles: bigint,
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
    model.signerDelegatedPerCycle.set(
      sdKey,
      (model.signerDelegatedPerCycle.get(sdKey) ?? 0n) - amountUstx,
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
function stxAccount(
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
