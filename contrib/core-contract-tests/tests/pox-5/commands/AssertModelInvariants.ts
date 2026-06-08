import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertSignerInfo,
  assertStakerInfo,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  currentRewardCycle,
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { MAX_SIGNERS } from '../pox-5-helpers';

/**
 * Standing-invariant sweep. On each fire, samples a random `(signer, staker)`
 * pair and asserts the contract's reads at the current cycle against the
 * model's stored per-cycle maps. Complements the in-command boundary checks
 * (which cover "did this Act populate its own first/last cycle"); this covers
 * "does the model agree with the contract at the current cycle."
 */
export const AssertModelInvariants = (accounts: Real['accounts']) => {
  const addresses = Object.values(accounts).map((a) => a.address);
  return fc
    .record({
      signerIndex: fc.nat({ max: MAX_SIGNERS - 1 }),
      stakerIndex: fc.nat({ max: addresses.length - 1 }),
    })
    .map((r) => {
      let sampled: string | undefined; // captured in run() for toString
      return {
        // Need at least one registered signer to probe. Stakers may be empty:
        // a non-staking principal is a valid probe whose membership/shares
        // must read as null/0, which broadens coverage beyond the active set.
        check: (model: Readonly<Model>) => model.signers.size > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'assert-model-invariants');

          // Arrange
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          // Probe the current cycle. The model mirrors the contract's
          // per-cycle maps (written for the exact cycles each Act touched,
          // never pruned), so cycle N reads back its stored value.
          const checkedCycle = currentRewardCycle(model);
          const signerIds = Array.from(model.signers.keys());
          const signer = signerIds[r.signerIndex % signerIds.length];
          // Probe staker is drawn from *all* wallets, not just current stakers,
          // so non-stakers exercise the null/zero side of every derivation.
          const staker = addresses[r.stakerIndex % addresses.length];
          sampled = `${signer.split('.').pop()}@${checkedCycle}, ${getWalletNameByAddress(staker)}`;

          // Assert

          // Per-cycle standing invariants at the current cycle, read from the
          // model's stored per-cycle maps. Unrolled; each helper is one
          // contract read.
          assertSignerDelegationForCycle(model, real, checkedCycle, signer);
          assertSignerCycleMembership(model, real, checkedCycle, staker);
          assertTotalDelegatedForCycle(model, real, checkedCycle);
          assertStakerSharesForCycle(model, real, checkedCycle, staker, signer);

          // Identity invariants: the contract's signer/staker records match
          // the model for the sampled principals (regardless of cycle). The
          // null-or-record derivation lives inside the helpers.
          assertSignerInfo(model.signers, real, signer);
          assertStakerInfo(model.stakers, real, staker);

          logCommand({
            action: 'assert-model-invariants',
            value: sampled,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () => `assert-model-invariants(${sampled ?? '?'})`,
      };
    });
};
