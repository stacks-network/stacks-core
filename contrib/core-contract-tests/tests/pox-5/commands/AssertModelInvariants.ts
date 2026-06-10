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
 * Picks any wallet plus a `check`-gated registered signer and asserts, against
 * the model at the current cycle, the whole-system aggregate
 * (`get-ustx-delegated-for-cycle`), staker identity (`get-staker-info`), and
 * per-cycle membership/shares (`get-signer-cycle-membership`,
 * `get-staker-shares-staked-for-cycle`).
 */
export const AssertModelInvariants = (accounts: Real['accounts']) => {
  const addresses = Object.values(accounts).map((a) => a.address);
  return fc
    .record({
      signer: fc.constantFrom(...candidateSignerIds),
      staker: fc.constantFrom(...addresses),
    })
    .map((r) => ({
      // Run only when the picked signer is registered; staker may be any
      // wallet.
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
        // Per-cycle staker-scoped reads at the current cycle (null/0 side for a
        // non-staker). No lock check — see the JSDoc above.
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
