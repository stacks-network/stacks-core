import fc from 'fast-check';
import type { Model, Real } from './types';
import { logCommand, refreshModel, trackCommandRun } from './utils';
import { expect } from 'vitest';

export const MineBitcoinBlocks = () =>
  fc
    .record({
      blocks: fc.integer({ min: 1, max: 50 }),
    })
    .map((r) => ({
      check: (_model: Readonly<Model>) => true,
      run: (model: Model, real: Real) => {
        trackCommandRun(model, 'mine-blocks');

        // Arrange
        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const expectedBurnAfter = bitcoinHeightBefore + r.blocks;

        // Act
        real.network.mineEmptyBurnBlocks(r.blocks);

        // Assert

        // Model was in sync with the real burn chain entering this command.
        expect(model.burnBlockHeight).toBe(BigInt(bitcoinHeightBefore));
        // simnet advanced the burn chain by exactly the amount requested.
        expect(real.network.burnBlockHeight).toBe(expectedBurnAfter);

        // Update model
        refreshModel(model, real);

        logCommand({
          action: 'mine-btc-blocks',
          value: `amount: ${r.blocks}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () => `mine-blocks(${r.blocks})`,
    }));
