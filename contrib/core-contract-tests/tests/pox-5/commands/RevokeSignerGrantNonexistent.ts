import fc from 'fast-check';
import type { Model, Real } from './types';
import { candidateSignerIds, logCommand, refreshModel } from './utils';
import { rovErr, txOk } from '@clarigen/test';
import { expect } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { errorCodes, signerAddress } from '../pox-5-helpers';

/**
 * Revoke a grant that was never created. `revoke-signer-grant` passes the auth
 * check (caller is the key's derived principal) and then map-delete returns
 * `false`.
 */
export const RevokeSignerGrantNonexistent = () =>
  fc
    .record({
      // 48 bytes for noble; yields a key never granted to any manager.
      seed: fc.uint8Array({ minLength: 48, maxLength: 48 }),
      // Static cap for legible shrinks; `%` wraps onto the live deployed
      // signer set.
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => {
      return {
        // Any deployed signer-manager works; the (fresh-key, manager) pair is
        // absent from signer-key-grants by construction.
        check: (model: Readonly<Model>) => model.deployedSigners.has(r.signer),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);

          // Arrange
          const signerSk = secp256k1.utils.randomSecretKey(r.seed);
          const signerKey = secp256k1.getPublicKey(signerSk, true);
          const signerManager = r.signer;
          const caller = signerAddress(signerKey);
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;

          // The model knows of no such grant; the contract agrees it is
          // absent.
          expect(
            rovErr(
              real.contracts.pox5.verifySignerKeyGrant({
                signerManager,
                signerKey,
              }),
            ),
          ).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);

          // Act
          const receipt = txOk(
            real.contracts.pox5.revokeSignerGrant({ signerManager, signerKey }),
            caller,
          );

          // Assert

          // Receipt tuple reports `existed: false`: there was nothing to
          // delete.
          expect(receipt.value.existed).toBe(false);

          logCommand({
            action: 'revoke-signer-grant-nonexistent',
            value: signerManager.split('.').pop(),
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `revoke-signer-grant-nonexistent(${r.signer.split('.').pop()})`,
      };
    });
