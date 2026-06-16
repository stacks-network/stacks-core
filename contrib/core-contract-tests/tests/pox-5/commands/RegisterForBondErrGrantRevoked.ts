import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondAllowanceKey,
  candidateSignerIds,
  getWalletNameByAddress,
  isInPreparePhase,
  logCommand,
  minUstxForSats,
  refreshModel,
  registrableBondsForStaker,
  revokedSigners,
  trackCommandRun,
} from './utils';
import { err } from '@clarigen/core';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * register-for-bond with a registered signer whose current key grant was
 * revoked. The signer row is found, then grant verification reports not-found.
 */
export const RegisterForBondErrGrantRevoked = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      bondPick: fc.nat(),
      signer: fc.constantFrom(...candidateSignerIds),
      satsBips: fc.bigInt({ min: 1n, max: 10000n }),
      extraUstx: fc.bigInt({ min: 1n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          revokedSigners(model).includes(r.signer) &&
          !model.stakers.has(r.sender) &&
          (model.sbtcBalances.get(r.sender) ?? 0n) > 0n &&
          registrableBondsForStaker(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_grant_revoked');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = registrableBondsForStaker(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const config = model.bonds.get(bondIndex)!;
          const allowance = model.bondAllowances.get(
            bondAllowanceKey(bondIndex, r.sender),
          )!;
          const balance = model.sbtcBalances.get(r.sender)!;
          const maxSats = allowance < balance ? allowance : balance;
          const satsBase = (maxSats * r.satsBips) / 10000n;
          const sats = satsBase > 0n ? satsBase : 1n;
          const amountUstx =
            minUstxForSats(sats, config.stxValueRatio, config.minUstxRatio) +
            r.extraUstx;
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
              signerManager: r.signer,
              amountUstx,
              btcLockup: err(sats),
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          expect(membershipBefore).toBeNull();
          expect(receipt.value).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            membershipBefore,
          );
          expect(sbtcBalance(r.sender)).toBe(balanceBefore);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalStakedBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'register-for-bond-err-grant-revoked',
            value: `bond ${bondIndex}`,
            error: 'ERR_SIGNER_KEY_GRANT_NOT_FOUND',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-grant-revoked(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'}, ${r.signer.split('.').pop()})`,
      };
    });
