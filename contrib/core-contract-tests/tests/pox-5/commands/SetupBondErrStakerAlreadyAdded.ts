import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondAllowanceKey,
  eligibleBondIndex,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { deployer, errorCodes } from '../pox-5-helpers';
import { rov, txErr } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * setup-bond with the same staker repeated in the allowlist. The first insert
 * succeeds inside the fold, then the duplicate insert returns
 * ERR_STAKER_ALREADY_ADDED; the rejected public call leaves no bond config or
 * allowance behind.
 */
export const SetupBondErrStakerAlreadyAdded = (accounts: Real['accounts']) => {
  const addresses = Object.values(accounts).map((a) => a.address);
  return fc
    .record({
      staker: fc.constantFrom(...addresses),
      targetRate: fc.bigInt({ min: 1n, max: 10000n }),
      stxValueRatio: fc.bigInt({ min: 1n, max: 10000n }),
      minUstxRatio: fc.bigInt({ min: 1n, max: 10000n }),
      earlyUnlockBytes: fc.uint8Array({ maxLength: 100 }),
      firstMaxSats: fc.bigInt({ min: 0n, max: 1_000_000_000n }),
      secondMaxSats: fc.bigInt({ min: 0n, max: 1_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        check: (model: Readonly<Model>) => {
          const idx = eligibleBondIndex(model);
          return idx !== undefined && !model.bonds.has(idx);
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'setup-bond_err_staker_already_added');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bondIndex = eligibleBondIndex(model)!;
          pickedBond = bondIndex;
          const bondBefore = rov(
            real.contracts.pox5.getProtocolBond(bondIndex),
          );
          const allowanceBefore = rov(
            real.contracts.pox5.getBondAllowance(bondIndex, r.staker),
          );

          // Act

          const receipt = txErr(
            real.contracts.pox5.setupBond({
              bondIndex,
              targetRate: r.targetRate,
              stxValueRatio: r.stxValueRatio,
              minUstxRatio: r.minUstxRatio,
              earlyUnlockBytes: r.earlyUnlockBytes,
              allowlist: [
                { staker: r.staker, maxSats: r.firstMaxSats },
                { staker: r.staker, maxSats: r.secondMaxSats },
              ],
            }),
            deployer,
          );

          // Assert

          expect(bondBefore).toBeNull();
          expect(allowanceBefore).toBeNull();
          expect(receipt.value).toBe(errorCodes.ERR_STAKER_ALREADY_ADDED);
          expect(rov(real.contracts.pox5.getProtocolBond(bondIndex))).toEqual(
            bondBefore,
          );
          expect(
            rov(real.contracts.pox5.getBondAllowance(bondIndex, r.staker)),
          ).toEqual(allowanceBefore);
          expect(
            model.bondAllowances.has(bondAllowanceKey(bondIndex, r.staker)),
          ).toBe(false);

          logCommand({
            action: 'setup-bond-err-staker-already-added',
            value: `bond: ${bondIndex}`,
            error: 'ERR_STAKER_ALREADY_ADDED',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `setup-bond-err-staker-already-added(${pickedBond ?? '?'})`,
      };
    });
};
