import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  grantKey,
  logCommand,
  refreshModel,
  trackCommandRun,
  usedGrantKey,
} from './utils';
import { rov } from '@clarigen/test';
import { expect } from 'vitest';
import {
  MAX_SIGNERS,
  registerSigner,
  testSignerHandle,
} from '../pox-5-helpers';

/**
 * Re-register an already-registered signer with a brand-new key + grant,
 * exercising `register-signer`'s `map-set` overwrite semantics. The previous
 * grant stays live (rotation does not revoke it); only the recorded key moves.
 */
export const RotateSignerKey = () =>
  fc
    .record({
      // 48 bytes is what noble's randomSecretKey wants for a fresh key.
      seed: fc.uint8Array({ minLength: 48, maxLength: 48 }),
      // With a new key the (key, manager, auth-id) tuple is always unused, so
      // any auth-id works here.
      authId: fc.bigInt({ min: 1n, max: 1_000_000_000n }),
      // Static cap for legible shrinks; `%` wraps onto the live signer set.
      signerIndex: fc.nat({ max: MAX_SIGNERS - 1 }),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // Need an already-registered signer to rotate.
        check: (model: Readonly<Model>) => model.signers.size > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'rotate-signer-key');

          // Arrange

          const signerIds = Array.from(model.signers.keys());
          const signerId = signerIds[r.signerIndex % signerIds.length];
          pickedSigner = signerId;
          const handle = testSignerHandle(signerId);
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const prevKey = model.signers.get(signerId)!.signerKey;
          const signerInfoBefore = rov(
            real.contracts.pox5.getSignerInfo(signerId),
          );

          // Act

          // register-self grants the new key, then map-sets `signers` over the
          // existing entry.
          const { signerKey: newKey } = registerSigner({
            signerManager: handle,
            seed: r.seed,
            authId: r.authId,
          });

          // Assert

          // Pre-state matched the model's previously-recorded key.
          expect(signerInfoBefore).toEqual(prevKey);
          // The recorded key was overwritten with the new key.
          expect(rov(real.contracts.pox5.getSignerInfo(signerId))).toEqual(
            newKey,
          );

          // Update model

          // New grant is consumed and live; the previous grant stays live too.
          model.signers.set(signerId, { signerKey: newKey });
          model.usedGrants.add(usedGrantKey(newKey, signerId, r.authId));
          model.activeGrants.add(grantKey(newKey, signerId));

          logCommand({
            action: 'rotate-signer-key',
            value: signerId,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `rotate-signer-key(${pickedSigner ? pickedSigner.split('.').pop() : '?'})`,
      };
    });
