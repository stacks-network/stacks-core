import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  modelGetNewRewards,
  modelGetRewards,
  refreshModel,
} from './utils';
import { rov } from '@clarigen/test';
import { POX5_BOOT_ID, sbtcBalance, sbtcTransfer } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Fund the reward pool by sending raw sBTC to the contract principal. There is
 * no deposit entry point: `get-rewards` reads the contract's sBTC balance net
 * of staked sats and the reserve, so a plain transfer in is how new rewards
 * arrive.
 */
export const FundRewards = (accounts: Real['accounts']) =>
  fc
    .record({
      funder: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Reward-sized, kept well under genesis sBTC so the transfer succeeds.
      amountSats: fc.bigInt({ min: 1n, max: 1_000_000n }),
    })
    .map((r) => ({
      // The funder must hold the sats it is about to send.
      check: (model: Readonly<Model>) =>
        (model.sbtcBalances.get(r.funder) ?? 0n) >= r.amountSats,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const funderBefore = sbtcBalance(r.funder);

        // Act

        sbtcTransfer(r.amountSats, r.funder, POX5_BOOT_ID);

        // Update model
        model.contractSbtcBalance += r.amountSats;
        model.sbtcBalances.set(r.funder, funderBefore - r.amountSats);

        // Assert

        expect(sbtcBalance(r.funder)).toBe(funderBefore - r.amountSats);
        // The funded sats land entirely in the distributable reward pool.
        expect(rov(real.contracts.pox5.getRewards())).toBe(
          modelGetRewards(model),
        );
        expect(rov(real.contracts.pox5.getNewRewards())).toBe(
          modelGetNewRewards(model),
        );

        logCommand({
          sender: getWalletNameByAddress(r.funder),
          action: 'fund-rewards',
          value: `${r.amountSats} sats`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `fund-rewards(${getWalletNameByAddress(r.funder)}, ${r.amountSats})`,
    }));
