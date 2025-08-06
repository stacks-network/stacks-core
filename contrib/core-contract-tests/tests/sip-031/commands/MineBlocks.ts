import fc from "fast-check";
import type { Model, Real } from "./types";
import { logCommand, trackCommandRun } from "./utils";

export const MineBlocks = () =>
  fc.record({
    blocks: fc.integer({ min: 1, max: 100 }),
  }).map((r) => ({
    check: (model: Readonly<Model>) => model.initialized === true,
    run: (model: Model, _real: Real) => {
      trackCommandRun(model, "mine-blocks");

      simnet.mineEmptyBlocks(r.blocks);
      model.blockHeight += BigInt(r.blocks);

      logCommand({
        sender: undefined,
        status: "ok",
        action: "mine-blocks",
        value: `${r.blocks}`,
      });
    },
    toString: () => `mine-blocks ${r.blocks}`,
  }));
