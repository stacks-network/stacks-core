import fc from 'fast-check';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  logCommand,
  refreshModel,
  trackCommandRun,
  usedGrantKey,
} from './utils';
import { rov, rovErr, txErr } from '@clarigen/test';
import { errorCodes, pox5, testSignerHandle } from '../pox-5-helpers';
import { expect } from 'vitest';

const DUMMY_SIG = new Uint8Array(65);

/**
 * grant-signer-key with a malformed recoverable signature. The call goes
 * through the signer-manager wrapper so authorization passes, then
 * secp256k1-recover? returns ERR_INVALID_SIGNATURE_RECOVER.
 */
export const GrantSignerKeyErrInvalidSignatureRecover = () =>
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
        return !model.usedGrants.has(
          usedGrantKey(signerKey, r.signer, r.authId),
        );
      },
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'grant-signer-key_err_invalid_sig_recover');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const signerSk = secp256k1.utils.randomSecretKey(r.seed);
        const signerKey = secp256k1.getPublicKey(signerSk, true);
        const signerInfoBefore = rov(pox5.getSignerInfo(r.signer));
        const handle = testSignerHandle(r.signer);

        // Act

        const receipt = txErr(
          handle.registerSelf({
            signerManager: r.signer,
            signerKey,
            authId: r.authId,
            signerSig: DUMMY_SIG,
          }),
          real.accounts.deployer.address,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_INVALID_SIGNATURE_RECOVER);
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
          action: 'grant-signer-key-err-invalid-signature-recover',
          value: r.signer,
          error: 'ERR_INVALID_SIGNATURE_RECOVER',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `grant-signer-key-err-invalid-signature-recover(${r.signer
          .split('.')
          .pop()})`,
    }));
