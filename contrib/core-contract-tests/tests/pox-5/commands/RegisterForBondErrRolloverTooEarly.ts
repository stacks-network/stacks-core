import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondAllowanceKey,
  bondRolloverTargetsForStaker,
  bondRolloverUnlockHeight,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  logCommand,
  minUstxForSats,
  refreshModel,
  trackCommandRun,
} from './utils';
import { err } from '@clarigen/core';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * A bond member targets a later, non-overlapping bond before their current
 * bond's L1 unlock window. The overlap check passes, then rollover-window
 * validation rejects with ERR_ROLLOVER_TOO_EARLY.
 */
export const RegisterForBondErrRolloverTooEarly = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      bondPick: fc.nat(),
      signerPick: fc.nat(),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        check: (model: Readonly<Model>) => {
          const membership = model.bondMemberships.get(r.sender);
          return (
            membership !== undefined &&
            model.burnBlockHeight <
              bondRolloverUnlockHeight(model, membership.bondIndex) &&
            !isInPreparePhase(model) &&
            !model.stakers.has(r.sender) &&
            grantedSigners(model).length > 0 &&
            bondRolloverTargetsForStaker(model, r.sender).length > 0
          );
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_rollover_too_early');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = bondRolloverTargetsForStaker(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const signers = grantedSigners(model);
          const signer = signers[r.signerPick % signers.length];
          const config = model.bonds.get(bondIndex)!;
          const allowance = model.bondAllowances.get(
            bondAllowanceKey(bondIndex, r.sender),
          )!;
          const sats = allowance;
          const amountUstx =
            minUstxForSats(sats, config.stxValueRatio, config.minUstxRatio) +
            1n;
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.sender),
          );
          const balanceBefore = sbtcBalance(r.sender);
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );

          // Act

          const receipt = txErr(
            real.contracts.pox5.registerForBond({
              bondIndex,
              signerManager: signer,
              amountUstx,
              btcLockup: err(sats),
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          expect(membershipBefore).toEqual(model.bondMemberships.get(r.sender));
          expect(receipt.value).toBe(errorCodes.ERR_ROLLOVER_TOO_EARLY);
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            membershipBefore,
          );
          expect(sbtcBalance(r.sender)).toBe(balanceBefore);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalStakedBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'register-for-bond-err-rollover-too-early',
            value: `bond ${bondIndex}`,
            error: 'ERR_ROLLOVER_TOO_EARLY',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-rollover-too-early(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'})`,
      };
    });
