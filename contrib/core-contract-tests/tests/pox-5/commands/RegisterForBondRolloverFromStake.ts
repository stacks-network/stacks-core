import fc from 'fast-check';
import type { BondMembership, Model, Real } from './types';
import {
  assertBondSignerSharesForCycle,
  assertBondStakerSharesForCycle,
  assertBondTotalSharesForCycle,
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertSignerRewardsPerTokenForCycle,
  assertSignerRewardsPerTokenSettledForCycle,
  assertSignerUnclaimedRewardsForCycle,
  assertStakerRewardsPerTokenSettledForCycle,
  assertStakerSharesForCycle,
  assertStakerUnclaimedRewardsForCycle,
  assertTotalDelegatedForCycle,
  bondAllowanceKey,
  bondStartCycle,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  minUstxForSats,
  modelAddStakerToBondCycles,
  modelAddStakerToCycles,
  modelSettleBondRewards,
  refreshModel,
  stxRolloverBondTargetsForStaker,
} from './utils';
import { BOND_LENGTH_CYCLES, sbtcBalance } from '../pox-5-helpers';
import { err } from '@clarigen/core';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * Roll a non-overlapping STX-only stake into a protocol bond. The old
 * staker-info row is deleted, but its already-written per-cycle stake entries
 * remain through the old unlock cycle; the new bond writes start at the bond's
 * first reward cycle.
 */
export const RegisterForBondRolloverFromStake = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signerPick: fc.nat(),
      bondPick: fc.nat(),
      satsBips: fc.bigInt({ min: 1n, max: 10000n }),
      extraUstx: fc.bigInt({ min: 1n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          isStakerActive(model, r.sender) &&
          !model.bondMemberships.has(r.sender) &&
          grantedSigners(model).length > 0 &&
          (model.sbtcBalances.get(r.sender) ?? 0n) > 0n &&
          stxRolloverBondTargetsForStaker(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = stxRolloverBondTargetsForStaker(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const signers = grantedSigners(model);
          const signer = signers[r.signerPick % signers.length];
          const prevStake = model.stakers.get(r.sender)!;
          const config = model.bonds.get(bondIndex)!;
          const allowance = model.bondAllowances.get(
            bondAllowanceKey(bondIndex, r.sender),
          )!;
          const balance = model.sbtcBalances.get(r.sender)!;
          const maxSats = allowance < balance ? allowance : balance;
          const satsBase = (maxSats * r.satsBips) / 10000n;
          const sats = satsBase > 0n ? satsBase : 1n;
          const minAmountUstx =
            minUstxForSats(sats, config.stxValueRatio, config.minUstxRatio) +
            r.extraUstx;
          const amountUstx =
            minAmountUstx > prevStake.amountUstx
              ? minAmountUstx
              : prevStake.amountUstx;
          const firstRewardCycle = bondStartCycle(model, bondIndex);
          const lastCycle = firstRewardCycle + BOND_LENGTH_CYCLES - 1n;
          const membership: BondMembership = {
            bondIndex,
            amountUstx,
            signer,
            isL1Lock: false,
            amountSats: sats,
          };
          const stakerInfoBefore = rov(
            real.contracts.pox5.getStakerInfo(r.sender),
          );

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
          modelSettleBondRewards(
            model,
            signer,
            firstRewardCycle,
            bondIndex,
            r.sender,
          );
          model.stakers.delete(r.sender);
          model.sbtcBalances.set(r.sender, balance - sats);
          model.totalSbtcStaked += sats;
          model.contractSbtcBalance += sats;
          model.bondTotalStaked.set(
            bondIndex,
            (model.bondTotalStaked.get(bondIndex) ?? 0n) + sats,
          );
          model.bondMemberships.set(r.sender, membership);
          modelAddStakerToCycles(
            model,
            r.sender,
            signer,
            firstRewardCycle,
            BOND_LENGTH_CYCLES,
            amountUstx,
            false,
          );
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

          expect(stakerInfoBefore).toEqual({
            amountUstx: prevStake.amountUstx,
            firstRewardCycle: prevStake.firstRewardCycle,
            numCycles: prevStake.numCycles,
            signer: prevStake.signer,
          });
          expect(receipt.value.bondIndex).toBe(bondIndex);
          expect(receipt.value.satsTotal).toBe(sats);
          expect(receipt.value.amountUstx).toBe(amountUstx);
          expect(receipt.value.firstRewardCycle).toBe(firstRewardCycle);
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toBeNull();
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
          assertSignerUnclaimedRewardsForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            signer,
          );
          assertSignerRewardsPerTokenSettledForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            signer,
          );
          assertSignerRewardsPerTokenForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            signer,
          );
          assertStakerUnclaimedRewardsForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            signer,
            r.sender,
          );
          assertStakerRewardsPerTokenSettledForCycle(
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
          assertStakerRewardsPerTokenSettledForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            signer,
            r.sender,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'register-for-bond-rollover-from-stake',
            value: `bond ${bondIndex} sats ${sats}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-rollover-from-stake(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'})`,
      };
    });
