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
 * `setup-bond` for a bond more than BOND_GAP_CYCLES cycles ahead reverts
 * ERR_CANNOT_SETUP_BOND_TOO_SOON. Targets the bond after the open window
 * (`eligible + 1`), whose start (>= 2 cycles, so no underflow shortcut) is more
 * than one gap beyond the current height.
 */
export const SetupBondErrTooSoon = (accounts: Real['accounts']) => {
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
        check: (model: Readonly<Model>) =>
          eligibleBondIndex(model) !== undefined,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'setup-bond_err_too_soon');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bondIndex = eligibleBondIndex(model)! + 1n;
          pickedBond = bondIndex;
          const expected = model.bonds.get(bondIndex) ?? null;

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

          expect(receipt.value).toBe(errorCodes.ERR_CANNOT_SETUP_BOND_TOO_SOON);
          // Setup state for that index is unchanged.
          expect(rov(real.contracts.pox5.getProtocolBond(bondIndex))).toEqual(
            expected,
          );

          logCommand({
            action: 'setup-bond-err-too-soon',
            value: `bond: ${bondIndex}`,
            error: 'ERR_CANNOT_SETUP_BOND_TOO_SOON',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () => `setup-bond-err-too-soon(${pickedBond ?? '?'})`,
      };
    });
};
