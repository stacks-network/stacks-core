import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondAllowanceKey,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  isStakerActive,
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
 * Registrable bonds whose allowance is below the staker's sBTC balance, so a
 * sats amount strictly above the allowance but within balance exists. That is
 * the only way to overshoot the allowance without first failing the balance
 * check.
 */
function overshootableBonds(model: Readonly<Model>, staker: string): bigint[] {
  const balance = model.sbtcBalances.get(staker) ?? 0n;
  return registrableBondsForStaker(model, staker).filter((bondIndex) => {
    const allowance = model.bondAllowances.get(
      bondAllowanceKey(bondIndex, staker),
    )!;
    return allowance < balance;
  });
}

/**
 * Register for a registrable bond with more sats than the allowance permits.
 * The sender clears the amount floor and carries no overlapping stake, so the
 * `<= sats-total allowance` assertion is the gate that trips: the call reverts
 * with ERR_TOO_MUCH_SATS and mutates nothing.
 */
export const RegisterForBondErrTooMuchSats = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      bondPick: fc.nat(),
      signerIndex: fc.nat(),
      // Fraction of the (allowance, balance] gap to overshoot by, in basis
      // points. Always lands the sats strictly above the allowance.
      overshootBips: fc.bigInt({ min: 1n, max: 10000n }),
      extraUstx: fc.bigInt({ min: 0n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      let pickedSigner: string | undefined;
      return {
        // A registrable bond whose allowance is under the balance, a sender
        // with no active stake (so the already-staked check can't fire first),
        // and not the prepare phase leave the too-much-sats check as the gate.
        // A granted signer keeps the handle well formed.
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          grantedSigners(model).length > 0 &&
          !isStakerActive(model, r.sender) &&
          overshootableBonds(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_too_much_sats');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = overshootableBonds(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const config = model.bonds.get(bondIndex)!;
          const allowance = model.bondAllowances.get(
            bondAllowanceKey(bondIndex, r.sender),
          )!;
          const balance = model.sbtcBalances.get(r.sender)!;
          // sats strictly above the allowance, capped at balance: at least
          // allowance + 1, at most balance.
          const gap = balance - allowance;
          const overshoot = (gap * r.overshootBips) / 10000n;
          const sats = allowance + (overshoot > 0n ? overshoot : 1n);
          // Clear the amount floor; that check sits before the too-much-sats
          // one, so it must not fire first.
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

          // sats overshoots the allowance but stays within balance.
          expect(sats).toBeGreaterThan(allowance);
          expect(sats).toBeLessThanOrEqual(balance);

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
          expect(receipt.value).toBe(errorCodes.ERR_TOO_MUCH_SATS);
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
            action: 'register-for-bond-err-too-much-sats',
            value: `bond ${bondIndex} sats ${sats}`,
            error: 'ERR_TOO_MUCH_SATS',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-too-much-sats(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'}${
            pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''
          })`,
      };
    });
