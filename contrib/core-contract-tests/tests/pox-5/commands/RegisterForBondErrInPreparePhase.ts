import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondAllowanceKey,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  logCommand,
  minUstxForSats,
  refreshModel,
  registrableBondsForStaker,
  trackCommandRun,
} from './utils';
import { err } from '@clarigen/core';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Register for a bond during the prepare phase. `verify-not-prepare-phase`
 * runs right after the bond and allowance lookups, so an otherwise-registrable
 * bond reverts with ERR_STAKE_IN_PREPARE_PHASE before the amount checks and
 * mutates nothing.
 */
export const RegisterForBondErrInPreparePhase = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      bondPick: fc.nat(),
      signerIndex: fc.nat(),
      sats: fc.bigInt({ min: 1n, max: 1_000_000n }),
      extraUstx: fc.bigInt({ min: 0n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      let pickedSigner: string | undefined;
      return {
        // A registrable bond (set up, allowlisted, fresh, not started) plus
        // the prepare phase leaves the prepare-phase guard as the only revert
        // reason. A granted signer keeps the handle well formed.
        check: (model: Readonly<Model>) =>
          isInPreparePhase(model) &&
          grantedSigners(model).length > 0 &&
          registrableBondsForStaker(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_in_prepare_phase');

          // Arrange
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = registrableBondsForStaker(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const config = model.bonds.get(bondIndex)!;
          const allowance = model.bondAllowances.get(
            bondAllowanceKey(bondIndex, r.sender),
          )!;
          // Stay within the allowance and pass the amount floor; both checks
          // sit after the prepare-phase guard, so neither can fire first.
          const balance = model.sbtcBalances.get(r.sender) ?? 0n;
          const maxSats = allowance < balance ? allowance : balance;
          const satsBase = r.sats < maxSats ? r.sats : maxSats;
          const sats = satsBase > 0n ? satsBase : 1n;
          const amountUstx =
            minUstxForSats(sats, config.stxValueRatio, config.minUstxRatio) +
            r.extraUstx;
          const balanceBefore = sbtcBalance(r.sender);
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.sender),
          );
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

          // Pre-state matched the model: no membership, the model's staked
          // total.
          expect(membershipBefore).toBeNull();
          expect(totalStakedBefore).toBe(model.totalSbtcStaked);
          expect(receipt.value).toBe(errorCodes.ERR_STAKE_IN_PREPARE_PHASE);
          // Rejected call left membership, sBTC custody, and the staked total
          // untouched.
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            membershipBefore,
          );
          expect(sbtcBalance(r.sender)).toBe(balanceBefore);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalStakedBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'register-for-bond-err-in-prepare-phase',
            value: `bond ${bondIndex}`,
            error: 'ERR_STAKE_IN_PREPARE_PHASE',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-in-prepare-phase(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'}${
            pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''
          })`,
      };
    });
