import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  assertSignerDelegationForCycle,
  assertSignerInfo,
  candidateSignerIds,
  currentRewardCycle,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';

/**
 * Standing-invariant sweep over signers (decoupled from any Act). Picks a
 * signer-manager id from the static candidate set, `check`-gates it to a
 * registered one, and asserts its signer-scoped reads against the model:
 * identity (`get-signer-info`) and per-cycle delegation
 * (`get-amount-delegated-for-signer`) at the current cycle.
 */
export const AssertSignerInvariants = () => {
  return fc
    .record({
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      // Run only when the picked candidate is actually registered.
      check: (model: Readonly<Model>) => model.signers.has(r.signer),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'assert-signer-invariants');

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const checkedCycle = currentRewardCycle(model);

        // Identity invariant; null-or-key derivation lives in the helper.
        assertSignerInfo(model.signers, real, r.signer);
        // Per-cycle delegation at the current cycle.
        assertSignerDelegationForCycle(model, real, checkedCycle, r.signer);

        logCommand({
          action: 'assert-signer-invariants',
          value: `${r.signer.split('.').pop()}@${checkedCycle}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () => `assert-signer-invariants(${r.signer.split('.').pop()})`,
    }));
};
