import fc from 'fast-check';
import type { BondMembership, Model, Real } from './types';
import {
  assertBondSignerSharesForCycle,
  assertBondStakerSharesForCycle,
  assertBondTotalSharesForCycle,
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  bondAllowanceKey,
  bondStartCycle,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  logCommand,
  minUstxForSats,
  modelAddStakerToBondCycles,
  modelAddStakerToCycles,
  refreshModel,
  registrableBondsForStaker,
  trackCommandRun,
} from './utils';
import { BOND_LENGTH_CYCLES, sbtcBalance } from '../pox-5-helpers';
import { err } from '@clarigen/core';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * A fresh staker registers sBTC for a set-up, not-yet-started bond. Moves
 * `sats` sBTC into custody, records the membership, and joins the signer
 * across the bond's whole term. Asserts the membership, sBTC custody, the
 * per-cycle signer delegation, and the bond per-cycle shares (total, signer,
 * staker) at the first and last cycle read back. Bond members and stx-only
 * stakers are kept disjoint, so the staker is gated out of an existing
 * stx-stake.
 */
export const RegisterForBond = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signerIndex: fc.nat(),
      bondPick: fc.nat(),
      // sats in (0, min(allowance, balance)]; >= 1 so the registration
      // actually custodies sBTC.
      satsBips: fc.bigInt({ min: 1n, max: 10000n }),
      // Locked uSTX above the contract minimum, well under the staker's
      // genesis STX so the total-balance check passes.
      extraUstx: fc.bigInt({ min: 1n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      let pickedSigner: string | undefined;
      return {
        // A registrable bond, a granted signer, sBTC to stake, no stx-stake to
        // conflict, and not in the prepare phase (the first guard).
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          grantedSigners(model).length > 0 &&
          (model.sbtcBalances.get(r.sender) ?? 0n) > 0n &&
          !model.stakers.has(r.sender) &&
          registrableBondsForStaker(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond');

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
          const balance = model.sbtcBalances.get(r.sender)!;
          const maxSats = allowance < balance ? allowance : balance;
          const satsBase = (maxSats * r.satsBips) / 10000n;
          const sats = satsBase > 0n ? satsBase : 1n;
          const amountUstx =
            minUstxForSats(sats, config.stxValueRatio, config.minUstxRatio) +
            r.extraUstx;
          const firstRewardCycle = bondStartCycle(model, bondIndex);
          const lastCycle = firstRewardCycle + BOND_LENGTH_CYCLES - 1n;
          const membership: BondMembership = {
            bondIndex,
            amountUstx,
            signer,
            isL1Lock: false,
            amountSats: sats,
          };

          // Act

          const receipt = txOk(
            real.contracts.pox5.registerForBond({
              bondIndex,
              signerManager: signer,
              amountUstx,
              btcLockup: err(sats),
              signerCalldata: null,
            }),
            r.sender,
          );

          // Update model
          model.sbtcBalances.set(r.sender, balance - sats);
          model.totalSbtcStaked += sats;
          model.bondTotalStaked.set(
            bondIndex,
            (model.bondTotalStaked.get(bondIndex) ?? 0n) + sats,
          );
          model.bondMemberships.set(r.sender, membership);
          // Bond delegation joins the signer cycles with stx-staking false, so
          // the stx-only staker-shares stay 0.
          modelAddStakerToCycles(
            model,
            r.sender,
            signer,
            firstRewardCycle,
            BOND_LENGTH_CYCLES,
            amountUstx,
            false,
          );
          // Bond shares (the some bond-index maps) move by the sats amount.
          modelAddStakerToBondCycles(
            model,
            r.sender,
            signer,
            bondIndex,
            firstRewardCycle,
            BOND_LENGTH_CYCLES,
            sats,
          );

          // Assert

          // Receipt echoes the registration.
          expect(receipt.value.bondIndex).toBe(bondIndex);
          expect(receipt.value.satsTotal).toBe(sats);
          expect(receipt.value.amountUstx).toBe(amountUstx);
          expect(receipt.value.firstRewardCycle).toBe(firstRewardCycle);
          // Membership and sBTC custody read back.
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            membership,
          );
          expect(sbtcBalance(r.sender)).toBe(balance - sats);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            model.totalSbtcStaked,
          );
          expect(
            rov(real.contracts.pox5.getTotalSbtcStakedForBond(bondIndex)),
          ).toBe(model.bondTotalStaked.get(bondIndex)!);
          // Per-cycle signer delegation at the bond's first and last cycle.
          assertSignerDelegationForCycle(model, real, firstRewardCycle, signer);
          assertSignerCycleMembership(model, real, firstRewardCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, firstRewardCycle);
          assertStakerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            r.sender,
            signer,
          );
          // Bond shares at the first cycle: total, this signer, this staker.
          assertBondTotalSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
          );
          assertBondSignerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            signer,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            signer,
            r.sender,
          );
          assertSignerDelegationForCycle(model, real, lastCycle, signer);
          assertSignerCycleMembership(model, real, lastCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, lastCycle);
          assertStakerSharesForCycle(model, real, lastCycle, r.sender, signer);
          // Bond shares at the last cycle.
          assertBondTotalSharesForCycle(model, real, lastCycle, bondIndex);
          assertBondSignerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            signer,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            signer,
            r.sender,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'register-for-bond',
            value: `bond ${bondIndex} sats ${sats}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond(${getWalletNameByAddress(r.sender)}, bond ${
            pickedBond ?? '?'
          }${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
