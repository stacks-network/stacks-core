import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  assertSignerCycleMembership,
  assertStakerInfo,
  assertStakerLock,
  assertStakerSharesForCycle,
  currentRewardCycle,
  getWalletNameByAddress,
  isStakerInCurrentCycle,
  logCommand,
  modelStakerSignerForCycle,
  refreshModel,
  trackCommandRun,
} from './utils';

/**
 * Standing-invariant sweep over active stakers (decoupled from any Act).
 * Samples a wallet, `check`-gated to one holding a position in the current
 * cycle, so every read hits the non-null side: identity, the runtime STX lock,
 * and per-cycle membership/shares. The shares read uses the model's per-cycle
 * signer (which a mid-lock signer change can make differ from the staker's
 * latest), guaranteed to exist by `check`.
 */
export const AssertStakerInvariants = (accounts: Real['accounts']) => {
  const addresses = Object.values(accounts).map((a) => a.address);
  return fc
    .record({
      staker: fc.constantFrom(...addresses),
    })
    .map((r) => ({
      // Active in the current cycle, so its lock and per-cycle membership (and
      // thus the per-cycle signer) are both guaranteed to exist.
      check: (model: Readonly<Model>) =>
        isStakerInCurrentCycle(model, r.staker),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'assert-staker-invariants');

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const checkedCycle = currentRewardCycle(model);
        const signer = modelStakerSignerForCycle(
          model,
          r.staker,
          checkedCycle,
        )!;

        // Assert
        assertStakerInfo(model.stakers, real, r.staker);
        assertStakerLock(model, real, r.staker);
        assertSignerCycleMembership(model, real, checkedCycle, r.staker);
        assertStakerSharesForCycle(model, real, checkedCycle, r.staker, signer);

        logCommand({
          action: 'assert-staker-invariants',
          value: `${getWalletNameByAddress(r.staker)}@${checkedCycle}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `assert-staker-invariants(${getWalletNameByAddress(r.staker)})`,
    }));
};
