import type { Model, Real, StakerState } from './types';
import { accounts } from '../../clarigen-types';
import { rov } from '@clarigen/test';
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
  // Contract logic (get-staker-info): treats lock as expired once
  // first-reward-cycle + num-cycles <= current-pox-reward-cycle.
  // unlockCycle == first + num, so the staker is active while
  // current < unlockCycle.
  return currentRewardCycle(model) < staker.unlockCycle;
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

// Per-cycle model derivations. Each takes a snapshot of `stakers` (which the
// caller can construct as the "post-Act" view by copying model.stakers and
// applying the in-flight change) so assertions can compare contract state to
// what the model predicts without committing the change first.

function stakerActiveAtCycle(st: StakerState, cycle: bigint): boolean {
  return (
    st.firstRewardCycle <= cycle && cycle < st.firstRewardCycle + st.numCycles
  );
}

export function modelDelegatedForSigner(
  stakers: Map<string, StakerState>,
  signer: string,
  cycle: bigint,
): bigint {
  let sum = 0n;
  for (const st of stakers.values()) {
    if (st.signer === signer && stakerActiveAtCycle(st, cycle)) {
      sum += st.amountUstx;
    }
  }
  return sum;
}

export function modelTotalDelegated(
  stakers: Map<string, StakerState>,
  cycle: bigint,
): bigint {
  let sum = 0n;
  for (const st of stakers.values()) {
    if (stakerActiveAtCycle(st, cycle)) sum += st.amountUstx;
  }
  return sum;
}

export function modelSignerMembership(
  stakers: Map<string, StakerState>,
  staker: string,
  cycle: bigint,
): { amountUstx: bigint; signer: string } | null {
  const st = stakers.get(staker);
  if (!st || !stakerActiveAtCycle(st, cycle)) return null;
  return { amountUstx: st.amountUstx, signer: st.signer };
}

export function modelStakerShares(
  stakers: Map<string, StakerState>,
  staker: string,
  signer: string,
  cycle: bigint,
): bigint {
  const m = modelSignerMembership(stakers, staker, cycle);
  if (m && m.signer === signer) return m.amountUstx;
  return 0n;
}

// Per-cycle invariant checks. Each asserts one unconditional-write contract
// read against its model derivation. Intended for in-command "first locked"
// and "last locked" boundary assertions; broader sweeps live in
// AssertModelInvariants (Phase 2).

export function assertSignerDelegationForCycle(
  stakers: Map<string, StakerState>,
  real: Real,
  cycle: bigint,
  signer: string,
): void {
  expect(
    rov(real.contracts.pox5.getAmountDelegatedForSigner(signer, cycle)),
  ).toBe(modelDelegatedForSigner(stakers, signer, cycle));
}

export function assertStakerSharesForCycle(
  stakers: Map<string, StakerState>,
  real: Real,
  cycle: bigint,
  staker: string,
  signer: string,
): void {
  expect(
    rov(
      real.contracts.pox5.getStakerSharesStakedForCycle(
        staker,
        false,
        cycle,
        signer,
      ),
    ),
  ).toBe(modelStakerShares(stakers, staker, signer, cycle));
}

export function assertSignerCycleMembership(
  stakers: Map<string, StakerState>,
  real: Real,
  cycle: bigint,
  staker: string,
): void {
  expect(
    rov(real.contracts.pox5.getSignerCycleMembership(staker, cycle)),
  ).toEqual(modelSignerMembership(stakers, staker, cycle));
}

export function assertTotalDelegatedForCycle(
  stakers: Map<string, StakerState>,
  real: Real,
  cycle: bigint,
): void {
  expect(rov(real.contracts.pox5.getUstxDelegatedForCycle(cycle))).toBe(
    modelTotalDelegated(stakers, cycle),
  );
}
