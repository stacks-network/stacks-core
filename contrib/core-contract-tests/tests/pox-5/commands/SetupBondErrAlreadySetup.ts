import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  eligibleBondIndex,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { deployer, errorCodes } from '../pox-5-helpers';
import { rov, txErr } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * Re-`setup-bond` a bond that already exists. The timing checks pass (the
 * eligible bond's window is still open right after it was set up), then
 * `map-insert protocol-bonds` fails with ERR_BOND_ALREADY_SETUP, leaving the
 * stored config untouched.
 */
export const SetupBondErrAlreadySetup = (accounts: Real['accounts']) => {
  const addresses = Object.values(accounts).map((a) => a.address);
  return fc
    .record({
      targetRate: fc.bigInt({ min: 1n, max: 10000n }),
      stxValueRatio: fc.bigInt({ min: 1n, max: 10000n }),
      minUstxRatio: fc.bigInt({ min: 1n, max: 10000n }),
      earlyUnlockBytes: fc.uint8Array({ maxLength: 100 }),
      maxSats: fc.bigInt({ min: 0n, max: 1_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        // The bond whose window is open is already set up.
        check: (model: Readonly<Model>) => {
          const idx = eligibleBondIndex(model);
          return idx !== undefined && model.bonds.has(idx);
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'setup-bond_err_already_setup');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bondIndex = eligibleBondIndex(model)!;
          pickedBond = bondIndex;
          // The original config the bond must keep.
          const existing = model.bonds.get(bondIndex)!;

          // Act

          const receipt = txErr(
            real.contracts.pox5.setupBond({
              bondIndex,
              targetRate: r.targetRate,
              stxValueRatio: r.stxValueRatio,
              minUstxRatio: r.minUstxRatio,
              earlyUnlockBytes: r.earlyUnlockBytes,
              allowlist: addresses.map((staker) => ({
                staker,
                maxSats: r.maxSats,
              })),
            }),
            deployer,
          );

          // Assert

          expect(receipt.value).toBe(errorCodes.ERR_BOND_ALREADY_SETUP);
          // Stored config is unchanged (the original, not the new params).
          expect(rov(real.contracts.pox5.getProtocolBond(bondIndex))).toEqual(
            existing,
          );

          logCommand({
            action: 'setup-bond-err-already-setup',
            value: `bond: ${bondIndex}`,
            error: 'ERR_BOND_ALREADY_SETUP',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () => `setup-bond-err-already-setup(${pickedBond ?? '?'})`,
      };
    });
};
