import fc from 'fast-check';
import type { Model, Real } from './types';
import { logCommand, refreshModel, trackCommandRun } from './utils';
import { rovErr, txOk } from '@clarigen/test';
import { expect } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { MAX_SIGNERS, errorCodes, signerAddress } from '../pox-5-helpers';

/**
 * Revoke a grant that was never created. `revoke-signer-grant` passes the auth
 * check (caller is the key's derived principal) and then map-delete returns
 * `false`.
 */
export const RevokeSignerGrantNonexistent = () =>
  fc
    .record({
      // Fresh 48-byte seed yielding a key never granted to any manager (noble
      // wants 48).
      seed: fc.uint8Array({ minLength: 48, maxLength: 48 }),
      // Static cap for legible shrinks; `%` wraps onto the live deployed
      // signer set.
      signerIndex: fc.nat({ max: MAX_SIGNERS - 1 }),
    })
    .map((r) => {
      let target: string | undefined;
      return {
        // Any deployed signer-manager is a fine target principal. The
        // (fresh-key, manager) pair is guaranteed absent from
        // signer-key-grants by design.
        check: (model: Readonly<Model>) => model.deployedSigners.size > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'revoke-signer-grant_nonexistent');

          // Arrange
          const signerSk = secp256k1.utils.randomSecretKey(r.seed);
          const signerKey = secp256k1.getPublicKey(signerSk, true);
          const managers = Array.from(model.deployedSigners);
          const signerManager = managers[r.signerIndex % managers.length];
          target = signerManager.split('.').pop();
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

          // map-delete returns false: there was nothing to delete.
          expect(receipt.value).toBe(false);

          logCommand({
            action: 'revoke-signer-grant-nonexistent',
            value: target,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () => `revoke-signer-grant-nonexistent(${target ?? '?'})`,
      };
    });
