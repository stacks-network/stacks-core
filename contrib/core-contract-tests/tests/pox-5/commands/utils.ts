import type { Model, Real } from './types';
import { accounts } from '../../clarigen-types';

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

  const columnWidth = 23;
  const halfColumns = Math.floor(columnWidth / 2);
  const prettyPrint = items.map((content, index) =>
    index < 2 ? content.padEnd(halfColumns) : content.padEnd(columnWidth),
  );
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
