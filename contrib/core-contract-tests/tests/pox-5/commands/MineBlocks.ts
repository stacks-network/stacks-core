import fc from 'fast-check';
import type { Model, Real } from './types';
import { logCommand, refreshModel, trackCommandRun } from './utils';

export const MineBitcoinBlocks = () =>
  fc
    .record({
      blocks: fc.integer({ min: 1, max: 50 }),
    })
    .map((r) => ({
      check: (_model: Readonly<Model>) => true,
      run: (model: Model, real: Real) => {
        trackCommandRun(model, 'mine-blocks');

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;

        real.network.mineEmptyBurnBlocks(r.blocks);
        refreshModel(model, real);

        logCommand({
          action: 'mine-blocks',
          value: `${r.blocks}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () => `mine-blocks(${r.blocks})`,
    }));
