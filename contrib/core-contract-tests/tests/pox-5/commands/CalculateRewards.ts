import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  assertRewardsPerTokenForCycle,
  getWalletNameByAddress,
  logCommand,
  modelCalculateRewards,
  modelGetNewRewards,
  modelGetRewards,
  refreshModel,
  rewardsCalculationHeight,
  rptKey,
  trackCommandRun,
} from './utils';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * Run a reward distribution for the just-closed distribution (half) cycle.
 * Each active bond earns its target yield, the reserve skims its cut, and the
 * rest credits stx stakers through the none-pool accumulator. Callable once
 * per half-cycle: a rerun finds the snapshot height unmoved and aborts.
 */
export const CalculateRewards = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      // A new half-cycle must have closed since the last distribution, else
      // the call aborts with ERR_DISTRIBUTION_ALREADY_COMPUTED.
      check: (model: Readonly<Model>) =>
        rewardsCalculationHeight(model) > model.lastRewardComputeHeight,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'calculate-rewards');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const expected = modelCalculateRewards(model);

        // Act

        const receipt = txOk(
          real.contracts.pox5.calculateRewards({
            bondPeriods: expected.bondPeriods,
          }),
          r.sender,
        );

        // Update model

        for (const bond of expected.bondDistributions) {
          model.rewardsPerTokenForCycle.set(
            rptKey(expected.stxCycle, bond.bondIndex),
            bond.cumulativeRewardsPerSat,
          );
        }
        model.rewardsPerTokenForCycle.set(
          rptKey(expected.stxCycle, null),
          expected.cumulativeRewardsPerUstx,
        );
        model.reserveBalance = expected.newReserveBalance;
        model.lastRewardComputeHeight = expected.calculationHeight;
        model.lastAccountedRewardsOnly = expected.newLastAccounted;

        // Assert

        // Receipt echoes the whole distribution.
        expect(receipt.value.calculationHeight).toBe(
          expected.calculationHeight,
        );
        expect(receipt.value.stxCycle).toBe(expected.stxCycle);
        expect(receipt.value.grossAccruedRewards).toBe(
          expected.grossAccruedRewards,
        );
        expect(receipt.value.totalBondRewards).toBe(expected.totalBondRewards);
        expect(receipt.value.reserveDeposit).toBe(expected.reserveDeposit);
        expect(receipt.value.reserveBalance).toBe(expected.newReserveBalance);
        expect(receipt.value.totalStxStakerRewards).toBe(
          expected.stxStakerRewards,
        );
        expect(receipt.value.cycleStakedUstx).toBe(expected.cycleStakedUstx);
        expect(receipt.value.accruedRewardsPerUstx).toBe(
          expected.accruedRewardsPerUstx,
        );
        expect(receipt.value.cumulativeRewardsPerUstx).toBe(
          expected.cumulativeRewardsPerUstx,
        );
        // The none-pool accumulator and both snapshot vars read back.
        assertRewardsPerTokenForCycle(model, real, expected.stxCycle, null);
        expect(rov(real.contracts.pox5.getLastRewardComputeHeight())).toBe(
          expected.calculationHeight,
        );
        expect(rov(real.contracts.pox5.getLastAccountedRewardsOnly())).toBe(
          expected.newLastAccounted,
        );
        // Each active bond's accumulator, labelled so a miss names the bond.
        for (const bond of expected.bondDistributions) {
          expect(
            rov(
              real.contracts.pox5.getRewardsPerTokenForCycle(
                expected.stxCycle,
                bond.bondIndex,
              ),
            ),
            `rpt bond ${bond.bondIndex}`,
          ).toBe(bond.cumulativeRewardsPerSat);
        }
        // Distribution drains the new-rewards counter to nothing.
        expect(rov(real.contracts.pox5.getNewRewards())).toBe(
          modelGetNewRewards(model),
        );
        expect(rov(real.contracts.pox5.getRewards())).toBe(
          modelGetRewards(model),
        );

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'calculate-rewards',
          value: `cycle ${expected.stxCycle} gross ${expected.grossAccruedRewards} bonds ${expected.bondPeriods.length}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () => `calculate-rewards(${getWalletNameByAddress(r.sender)})`,
    }));
