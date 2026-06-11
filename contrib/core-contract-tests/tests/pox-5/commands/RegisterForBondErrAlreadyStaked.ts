import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondAllowanceKey,
  bondStartCycle,
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
 * Registrable bonds (set up, allowlisted, fresh, not started) whose first
 * cycle the staker's stx-only stake overlaps. The contract allows a stake only
 * when its term ends no later than the bond start, so `unlockCycle > bondStart`
 * (= `firstRewardCycle + numCycles > bondStart`) is the overlap that trips
 * ERR_ALREADY_STAKED.
 */
function overlappingRegistrableBonds(
  model: Readonly<Model>,
  staker: string,
): bigint[] {
  const stake = model.stakers.get(staker);
  if (!stake) return [];
  return registrableBondsForStaker(model, staker).filter(
    (bondIndex) => stake.unlockCycle > bondStartCycle(model, bondIndex),
  );
}

/**
 * Register for a bond whose first cycle the sender's stx-only stake overlaps.
 * The sender clears the amount floor and the bond has not started, so the
 * existing-stake check is the gate that trips: the call reverts with
 * ERR_ALREADY_STAKED before the too-much-sats check and mutates nothing.
 */
export const RegisterForBondErrAlreadyStaked = (accounts: Real['accounts']) =>
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
        // An active stx-staker with a registrable bond their stake overlaps,
        // outside the prepare phase, leaves the already-staked check as the
        // gate. isStakerActive keeps refreshModel from pruning the staker. A
        // granted signer keeps the handle well formed.
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          grantedSigners(model).length > 0 &&
          isStakerActive(model, r.sender) &&
          overlappingRegistrableBonds(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_already_staked');

          // Arrange
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = overlappingRegistrableBonds(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const config = model.bonds.get(bondIndex)!;
          const allowance = model.bondAllowances.get(
            bondAllowanceKey(bondIndex, r.sender),
          )!;
          // Stay within the allowance and clear the amount floor; both checks
          // sit before / after the already-staked one, so neither fires first.
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
          expect(receipt.value).toBe(errorCodes.ERR_ALREADY_STAKED);
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
            action: 'register-for-bond-err-already-staked',
            value: `bond ${bondIndex}`,
            error: 'ERR_ALREADY_STAKED',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-already-staked(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'}${
            pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''
          })`,
      };
    });
