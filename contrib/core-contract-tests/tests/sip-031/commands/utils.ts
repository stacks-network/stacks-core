import type { Model } from "./types";
import { accounts } from "../../clarigen-types";

export function calculateClaimable(model: Readonly<Model>): bigint {
  const c = model.constants;

  const max = c.INITIAL_MINT_VESTING_ITERATIONS;
  const amt = c.INITIAL_MINT_VESTING_AMOUNT;
  const per = c.STX_PER_ITERATION;
  const step = c.INITIAL_MINT_VESTING_ITERATION_BLOCKS;

  // If before deployment, nothing vested yet.
  const diff = model.blockHeight < model.deployBlockHeight
    ? 0n
    : model.blockHeight - model.deployBlockHeight;

  const iter = diff / step;
  const vest = iter >= max ? amt : per * iter;

  const total = c.INITIAL_MINT_IMMEDIATE_AMOUNT + vest;
  const reserved = c.INITIAL_MINT_AMOUNT - total;

  return model.balance > reserved ? model.balance - reserved : 0n;
}

export function logCommand({
  sender,
  status,
  action,
  value,
  error,
}: {
  sender?: string;
  status: "ok" | "err";
  action: string;
  value?: string | number | bigint;
  error?: string;
}) {
  const senderStr = (sender ?? "system").padEnd(11, " ");
  const statusStr = status === "ok" ? "✓" : "✗";
  const actionStr = action.padEnd(22, " ");

  let msg = `Ӿ ${senderStr} ${statusStr} ${actionStr}`;
  if (value !== undefined) msg += ` ${String(value)}`;
  if (error !== undefined) msg += ` error ${error}`;

  console.log(msg);
}

export function trackCommandRun(model: Model, commandName: string) {
  const count = model.statistics.get(commandName) || 0;
  model.statistics.set(commandName, count + 1);
}

export function reportCommandRuns(model: Model) {
  console.log("\nCommand execution counts:");
  const orderedStatistics = Array.from(model.statistics.entries()).sort(
    ([keyA], [keyB]) => {
      return keyA.localeCompare(keyB);
    },
  );

  logAsTree(orderedStatistics);
}

function logAsTree(statistics: [string, number][]) {
  const tree: { [key: string]: any } = {};

  statistics.forEach(([commandName, count]) => {
    const split = commandName.split("_");
    let root: string = split[0],
      rest: string = "base";

    if (split.length > 1) {
      rest = split.slice(1).join("_");
    }
    if (!tree[root]) {
      tree[root] = {};
    }
    tree[root][rest] = count;
  });

  const printTree = (node: any, indent: string = "") => {
    const keys = Object.keys(node);
    keys.forEach((key, index) => {
      const isLast = index === keys.length - 1;
      const boxChar = isLast ? "└─ " : "├─ ";
      if (key !== "base") {
        if (typeof node[key] === "object") {
          console.log(`${indent}${boxChar}${key}: x${node[key]["base"]}`);
          printTree(node[key], indent + (isLast ? "    " : "│   "));
        } else {
          console.log(`${indent}${boxChar}${key}: ${node[key]}`);
        }
      }
    });
  };

  printTree(tree);
}

export const getWalletNameByAddress = (address: string): string | undefined =>
  Object.entries(accounts).find(([, v]) => v.address === address)?.[0];
