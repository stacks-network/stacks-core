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

const DUMMY_SIG = new Uint8Array(65);

/**
 * Directly call grant-signer-key from a wallet while naming a signer-manager
 * contract. The authorization check runs before replay or signature checks, so
 * it rejects with ERR_UNAUTHORIZED_SIGNER_REGISTRATION and writes no grant.
 */
export const GrantSignerKeyErrUnauthorizedRegistration = () =>
  fc
    .record({
      signer: fc.constantFrom(...candidateSignerIds),
      seed: fc.uint8Array({ minLength: 48, maxLength: 48 }),
      authId: fc.bigInt({ min: 1n, max: 1_000_000_000n }),
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
          pox5.grantSignerKey({
            signerKey,
            signerManager: r.signer,
            authId: r.authId,
            signerSig: DUMMY_SIG,
          }),
          deployer,
        );

        // Assert

        expect(receipt.value).toBe(
          errorCodes.ERR_UNAUTHORIZED_SIGNER_REGISTRATION,
        );
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
          action: 'grant-signer-key-err-unauthorized',
          value: r.signer,
          error: 'ERR_UNAUTHORIZED_SIGNER_REGISTRATION',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `grant-signer-key-err-unauthorized(${r.signer.split('.').pop()})`,
    }));
