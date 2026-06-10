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
 * Standing-invariant sweep over active stakers (decoupled from any Act). Picks
 * a wallet from the static set and `check`-gates it to one holding a position
 * in the current cycle, so every read hits the non-null side: identity
 * (`get-staker-info`), the runtime STX lock, and per-cycle membership/shares.
 * The shares read uses the model's per-cycle signer (not the staker's latest —
 * a mid-lock signer change makes them differ), which `check` guarantees exists.
 */
export const AssertStakerInvariants = (accounts: Real['accounts']) => {
  const addresses = Object.values(accounts).map((a) => a.address);
  return fc
    .record({
      staker: fc.constantFrom(...addresses),
    })
    .map((r) => ({
      // Participating in the current cycle ⇒ active staker with a current-cycle
      // membership, so the lock and per-cycle signer are both guaranteed.
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
