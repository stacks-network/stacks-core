import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  eligibleBondIndex,
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { errorCodes } from '../pox-5-helpers';
import { rov, txErr } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * Non-admin attempt at `setup-bond`. The admin check is the first assertion, so
 * any caller other than `bond-admin` (the deployer) reverts ERR_UNAUTHORIZED
 * and no bond is created.
 */
export const SetupBondErrUnauthorized = (accounts: Real['accounts']) => {
  // Any wallet that isn't the bond-admin (deployer).
  const nonAdmins = Object.entries(accounts)
    .filter(([name]) => name !== 'deployer')
    .map(([, a]) => a.address);
  return fc
    .record({
      caller: fc.constantFrom(...nonAdmins),
      targetRate: fc.bigInt({ min: 1n, max: 10000n }),
      stxValueRatio: fc.bigInt({ min: 1n, max: 10000n }),
      minUstxRatio: fc.bigInt({ min: 1n, max: 10000n }),
      earlyUnlockBytes: fc.uint8Array({ maxLength: 100 }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        // Target the open, not-yet-setup bond so the only reason for rejection
        // is the unauthorized caller.
        check: (model: Readonly<Model>) => {
          const idx = eligibleBondIndex(model);
          return idx !== undefined && !model.bonds.has(idx);
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'setup-bond_err_unauthorized');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bondIndex = eligibleBondIndex(model)!;
          pickedBond = bondIndex;

          // Act

          const receipt = txErr(
            real.contracts.pox5.setupBond({
              bondIndex,
              targetRate: r.targetRate,
              stxValueRatio: r.stxValueRatio,
              minUstxRatio: r.minUstxRatio,
              earlyUnlockBytes: r.earlyUnlockBytes,
              allowlist: [],
            }),
            r.caller,
          );

          // Assert

          expect(receipt.value).toBe(errorCodes.ERR_UNAUTHORIZED);
          // No bond was created.
          expect(
            rov(real.contracts.pox5.getProtocolBond(bondIndex)),
          ).toBeNull();

          logCommand({
            sender: getWalletNameByAddress(r.caller),
            action: 'setup-bond-err-unauthorized',
            value: `bond: ${bondIndex}`,
            error: 'ERR_UNAUTHORIZED',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `setup-bond-err-unauthorized(${getWalletNameByAddress(r.caller)}, ${pickedBond ?? '?'})`,
      };
    });
};
