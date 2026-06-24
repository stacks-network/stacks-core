import fc from 'fast-check';
import type { BondMembership, Model, Real } from './types';
import {
  assertBondSignerSharesForCycle,
  assertBondStakerSharesForCycle,
  assertBondTotalSharesForCycle,
  assertSignerRewardsPerTokenForCycle,
  assertSignerRewardsPerTokenSettledForCycle,
  assertSignerUnclaimedRewardsForCycle,
  assertStakerRewardsPerTokenSettledForCycle,
  assertStakerUnclaimedRewardsForCycle,
  bondEndCycle,
  bondStartCycle,
  currentRewardCycle,
  getWalletNameByAddress,
  isActiveBondMember,
  isInPreparePhase,
  logCommand,
  modelStakerSignerForCycle,
  modelUnstakeSatsFromBondCycles,
  refreshModel,
} from './utils';
import { sbtcBalance } from '../pox-5-helpers';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * A bond participant withdraws part or all of their custodied sBTC. Returns
 * the sats to the staker, lowers the membership's amount-sats and the staked
 * totals, and re-bases the bond per-cycle shares from the affected cycle to
 * the bond end. The STX delegation is untouched, so only the bond-variant
 * shares move. Gated to an active member so the affected range is non-empty
 * and the membership still reads back.
 */
export const UnstakeSbtc = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Withdraw a fraction of the custodied sats; >= 1 so the call moves sBTC.
      withdrawalBips: fc.bigInt({ min: 1n, max: 10000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        // An active member with custodied sBTC to withdraw, outside the prepare
        // phase. sBTC bonds only (is-l1-lock false); L1 locks cannot
        // unstake-sbtc.
        check: (model: Readonly<Model>) => {
          const membership = model.bondMemberships.get(r.sender);
          return (
            isActiveBondMember(model, r.sender) &&
            membership !== undefined &&
            !membership.isL1Lock &&
            membership.amountSats > 0n &&
            !isInPreparePhase(model)
          );
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const membership = model.bondMemberships.get(r.sender)!;
          const { signer, bondIndex, amountSats } = membership;
          pickedBond = bondIndex;
          const withdrawalBase = (amountSats * r.withdrawalBips) / 10000n;
          const clampedBase =
            withdrawalBase < amountSats ? withdrawalBase : amountSats;
          const withdrawal = clampedBase > 0n ? clampedBase : 1n;
          const newAmountSats = amountSats - withdrawal;
          const current = currentRewardCycle(model);
          const bondStart = bondStartCycle(model, bondIndex);
          const bondEnd = bondEndCycle(model, bondIndex);
          // clamp(current, bondStart, bondEnd): the change starts at the
          // current cycle, floored at the bond start when it has not begun.
          const firstChanged = current < bondStart ? bondStart : current;
          const numCycles = bondEnd - firstChanged;
          const lastCycle = bondEnd - 1n;
          const balanceBefore = sbtcBalance(r.sender);
          const newMembership: BondMembership = {
            ...membership,
            amountSats: newAmountSats,
          };
          const firstChangedSigner = modelStakerSignerForCycle(
            model,
            r.sender,
            firstChanged,
          );
          const lastCycleSigner = modelStakerSignerForCycle(
            model,
            r.sender,
            lastCycle,
          );
          if (firstChangedSigner === undefined) {
            throw new Error(
              `Missing signer-cycle membership for ${r.sender} at cycle ${firstChanged}`,
            );
          }
          if (lastCycleSigner === undefined) {
            throw new Error(
              `Missing signer-cycle membership for ${r.sender} at cycle ${lastCycle}`,
            );
          }

          // Act

          const receipt = txOk(
            real.contracts.pox5.unstakeSbtc({
              signerManager: signer,
              amountToWithdrawalSats: withdrawal,
            }),
            r.sender,
          );

          // Update model

          // The contract re-bases each affected cycle under that cycle's
          // signer, not necessarily the membership's latest signer. Only the
          // bond-variant shares move; the STX delegation is unchanged.
          modelUnstakeSatsFromBondCycles(
            model,
            r.sender,
            bondIndex,
            firstChanged,
            numCycles,
            withdrawal,
            newAmountSats,
          );
          model.bondMemberships.set(r.sender, newMembership);
          model.bondTotalStaked.set(
            bondIndex,
            model.bondTotalStaked.get(bondIndex)! - withdrawal,
          );
          model.totalSbtcStaked -= withdrawal;
          model.contractSbtcBalance -= withdrawal;
          model.sbtcBalances.set(
            r.sender,
            (model.sbtcBalances.get(r.sender) ?? 0n) + withdrawal,
          );

          // Assert

          // Receipt echoes the withdrawal.
          expect(receipt.value.staker).toBe(r.sender);
          expect(receipt.value.signer).toBe(signer);
          expect(receipt.value.bondIndex).toBe(bondIndex);
          expect(receipt.value.amountWithdrawnSats).toBe(withdrawal);
          expect(receipt.value.newAmountSats).toBe(newAmountSats);
          // Membership keeps everything but the lowered amount-sats.
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            newMembership,
          );
          // sBTC returned to the staker; staked totals lowered.
          expect(sbtcBalance(r.sender)).toBe(balanceBefore + withdrawal);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            model.totalSbtcStaked,
          );
          expect(
            rov(real.contracts.pox5.getTotalSbtcStakedForBond(bondIndex)),
          ).toBe(model.bondTotalStaked.get(bondIndex)!);
          // Bond per-cycle shares re-based at the first affected and last cycle.
          assertBondTotalSharesForCycle(model, real, firstChanged, bondIndex);
          assertBondSignerSharesForCycle(
            model,
            real,
            firstChanged,
            bondIndex,
            firstChangedSigner,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            firstChanged,
            bondIndex,
            firstChangedSigner,
            r.sender,
          );
          assertSignerUnclaimedRewardsForCycle(
            model,
            real,
            firstChanged,
            bondIndex,
            firstChangedSigner,
          );
          assertSignerRewardsPerTokenSettledForCycle(
            model,
            real,
            firstChanged,
            bondIndex,
            firstChangedSigner,
          );
          assertSignerRewardsPerTokenForCycle(
            model,
            real,
            firstChanged,
            bondIndex,
            firstChangedSigner,
          );
          assertStakerUnclaimedRewardsForCycle(
            model,
            real,
            firstChanged,
            bondIndex,
            firstChangedSigner,
            r.sender,
          );
          assertStakerRewardsPerTokenSettledForCycle(
            model,
            real,
            firstChanged,
            bondIndex,
            firstChangedSigner,
            r.sender,
          );
          assertBondTotalSharesForCycle(model, real, lastCycle, bondIndex);
          assertBondSignerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            lastCycleSigner,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            lastCycleSigner,
            r.sender,
          );
          assertSignerUnclaimedRewardsForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            lastCycleSigner,
          );
          assertSignerRewardsPerTokenSettledForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            lastCycleSigner,
          );
          assertSignerRewardsPerTokenForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            lastCycleSigner,
          );
          assertStakerUnclaimedRewardsForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            lastCycleSigner,
            r.sender,
          );
          assertStakerRewardsPerTokenSettledForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            lastCycleSigner,
            r.sender,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'unstake-sbtc',
            value: `bond ${bondIndex} sats ${withdrawal}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `unstake-sbtc(${getWalletNameByAddress(r.sender)}, bond ${
            pickedBond ?? '?'
          })`,
      };
    });
