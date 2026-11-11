import fc from 'fast-check';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  grantKey,
  logCommand,
  refreshModel,
} from './utils';
import { rov, rovErr, txErr } from '@clarigen/test';
import { deployer, errorCodes, pox5 } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Directly call register-signer with a signer-key that has no live grant for
 * the signer-manager. The grant lookup happens before caller authorization and
 * rejects with ERR_SIGNER_KEY_GRANT_NOT_FOUND.
 */
export const RegisterSignerErrGrantNotFound = () =>
  fc
    .record({
      signer: fc.constantFrom(...candidateSignerIds),
      seed: fc.uint8Array({ minLength: 48, maxLength: 48 }),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) => {
        if (!model.deployedSigners.has(r.signer)) return false;
        const signerSk = secp256k1.utils.randomSecretKey(r.seed);
        const signerKey = secp256k1.getPublicKey(signerSk, true);
        return !model.activeGrants.has(grantKey(signerKey, r.signer));
      },
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const signerSk = secp256k1.utils.randomSecretKey(r.seed);
        const signerKey = secp256k1.getPublicKey(signerSk, true);
        const signerInfoBefore = rov(pox5.getSignerInfo(r.signer));

        // Act

        const receipt = txErr(
          pox5.registerSigner({
            signerManager: r.signer,
            signerKey,
          }),
          deployer,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
        expect(rov(pox5.getSignerInfo(r.signer))).toEqual(signerInfoBefore);
        expect(
          rovErr(
            pox5.verifySignerKeyGrant({
              signerManager: r.signer,
              signerKey,
            }),
          ),
        ).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);

        logCommand({
          action: 'register-signer-err-grant-not-found',
          value: r.signer,
          error: 'ERR_SIGNER_KEY_GRANT_NOT_FOUND',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `register-signer-err-grant-not-found(${r.signer.split('.').pop()})`,
    }));
