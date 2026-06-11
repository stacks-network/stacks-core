import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  assertSignerCycleMembership,
  assertStakerInfo,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
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
