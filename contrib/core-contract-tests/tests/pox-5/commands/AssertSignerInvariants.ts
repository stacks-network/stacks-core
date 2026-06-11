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
 * Standing-invariant sweep over signers (decoupled from any Act). Samples a
 * signer-manager id from the static candidate set, `check`-gated to a
 * registered one, and asserts its signer-scoped reads against the model:
 * identity and per-cycle delegation at the current cycle.
 */
export const AssertSignerInvariants = () => {
  return fc
    .record({
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      // Picked candidate must be a registered signer.
      check: (model: Readonly<Model>) => model.signers.has(r.signer),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'assert-signer-invariants');

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const checkedCycle = currentRewardCycle(model);

        // Identity invariant; the null-or-key derivation lives in the helper.
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
