import fc from 'fast-check';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  logCommand,
  refreshModel,
  trackCommandRun,
  usedGrantKey,
} from './utils';
import { rov, rovErr, txErr } from '@clarigen/test';
import {
  errorCodes,
  pox5,
  signSignerKeyGrant,
  testSignerHandle,
} from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * grant-signer-key with a valid recoverable signature for one public key while
 * passing a different signer-key argument. Recovery succeeds, then the pubkey
 * equality check rejects with ERR_INVALID_SIGNATURE_PUBKEY.
 */
export const GrantSignerKeyErrInvalidSignaturePubkey = () =>
  fc
    .record({
      signer: fc.constantFrom(...candidateSignerIds),
      signingSeed: fc.uint8Array({ minLength: 48, maxLength: 48 }),
      passedSeed: fc.uint8Array({ minLength: 48, maxLength: 48 }),
      authId: fc.bigInt({ min: 1n, max: 1_000_000_000n }),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) => {
        if (!model.deployedSigners.has(r.signer)) return false;
        const signingSk = secp256k1.utils.randomSecretKey(r.signingSeed);
        const passedSk = secp256k1.utils.randomSecretKey(r.passedSeed);
        const signingKey = secp256k1.getPublicKey(signingSk, true);
        const passedKey = secp256k1.getPublicKey(passedSk, true);
        return (
          hex.encode(signingKey) !== hex.encode(passedKey) &&
          !model.usedGrants.has(usedGrantKey(passedKey, r.signer, r.authId))
        );
      },
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'grant-signer-key_err_invalid_sig_pubkey');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const signingSk = secp256k1.utils.randomSecretKey(r.signingSeed);
        const passedSk = secp256k1.utils.randomSecretKey(r.passedSeed);
        const passedKey = secp256k1.getPublicKey(passedSk, true);
        const signerSig = signSignerKeyGrant({
          signerManager: r.signer,
          authId: r.authId,
          signerSk: signingSk,
        });
        const signerInfoBefore = rov(pox5.getSignerInfo(r.signer));
        const handle = testSignerHandle(r.signer);

        // Act

        const receipt = txErr(
          handle.registerSelf({
            signerManager: r.signer,
            signerKey: passedKey,
            authId: r.authId,
            signerSig,
          }),
          real.accounts.deployer.address,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_INVALID_SIGNATURE_PUBKEY);
        expect(rov(pox5.getSignerInfo(r.signer))).toEqual(signerInfoBefore);
        expect(
          rovErr(
            pox5.verifySignerKeyGrant({
              signerManager: r.signer,
              signerKey: passedKey,
            }),
          ),
        ).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);

        logCommand({
          action: 'grant-signer-key-err-invalid-signature-pubkey',
          value: r.signer,
          error: 'ERR_INVALID_SIGNATURE_PUBKEY',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `grant-signer-key-err-invalid-signature-pubkey(${r.signer
          .split('.')
          .pop()})`,
    }));
