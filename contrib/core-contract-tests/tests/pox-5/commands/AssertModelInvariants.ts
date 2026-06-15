import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  assertContractSbtcBalance,
  assertCurrentPoxRewardCycle,
  assertPoxInfo,
  assertSbtcBalance,
  assertSignerCycleMembership,
  assertSignerPendingForCycle,
  assertSignerSetFirstForCycle,
  assertSignerSetItemForCycle,
  assertSignerSetLastForCycle,
  assertSignerSharesNoneForCycle,
  assertStakerInfo,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  assertTotalSharesNoneForCycle,
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';

/**
 * Standing-invariant sweep over the whole system (decoupled from any Act).
 * Samples any wallet plus a `check`-gated registered signer, so reads exercise
 * the non-staker (null/0) side too. Asserts, at the current cycle, the
 * whole-system aggregate, staker identity, and per-cycle membership/shares.
 */
export const AssertModelInvariants = (accounts: Real['accounts']) => {
  const addresses = Object.values(accounts).map((a) => a.address);
  return fc
    .record({
      signer: fc.constantFrom(...candidateSignerIds),
      staker: fc.constantFrom(...addresses),
    })
    .map((r) => ({
      // Picked signer must be registered; the staker may be any wallet.
      check: (model: Readonly<Model>) => model.signers.has(r.signer),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'assert-model-invariants');

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const checkedCycle = currentRewardCycle(model);

        // Whole-system per-cycle aggregate at the current cycle.
        assertCurrentPoxRewardCycle(model, real);
        assertPoxInfo(model, real);
        assertTotalDelegatedForCycle(model, real, checkedCycle);
        // Identity invariant for the sampled (possibly non-)staker.
        assertStakerInfo(model.stakers, real, r.staker);
        // Per-cycle staker-scoped reads at the current cycle (null/0 for a
        // non-staker). No lock check; the staker may not be active.
        assertSignerCycleMembership(model, real, checkedCycle, r.staker);
        assertStakerSharesForCycle(
          model,
          real,
          checkedCycle,
          r.staker,
          r.signer,
        );
        // None-variant (stx-only) threshold-gated reads at the current cycle:
        // the signer's unconditional pending sum, plus the signer/total shares
        // the contract writes only while delegation is over the threshold.
        assertSignerPendingForCycle(model, real, checkedCycle, r.signer);
        assertSignerSharesNoneForCycle(model, real, checkedCycle, r.signer);
        assertTotalSharesNoneForCycle(model, real, checkedCycle);
        assertSignerSetItemForCycle(model, real, checkedCycle, r.signer);
        assertSignerSetFirstForCycle(model, real, checkedCycle);
        assertSignerSetLastForCycle(model, real, checkedCycle);
        // sBTC balances: the sampled wallet's, plus the contract's whole-pool
        // balance that `get-rewards` derives from.
        assertSbtcBalance(model, r.staker);
        assertContractSbtcBalance(model);

        logCommand({
          action: 'assert-model-invariants',
          value: `${r.signer.split('.').pop()}@${checkedCycle}, ${getWalletNameByAddress(r.staker)}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `assert-model-invariants(${r.signer.split('.').pop()}, ${getWalletNameByAddress(r.staker)})`,
    }));
};
