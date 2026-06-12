import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  logCommand,
  parseGrantKey,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rovErr, rovOk, txOk } from '@clarigen/test';
import { expect } from 'vitest';
import { errorCodes, signerAddress } from '../pox-5-helpers';

/**
 * Revoke a live signer-key grant. Only the Stacks principal derived from the
 * signer key (`principal-construct?(hash160(key))`) may call it. map-delete
 * returns `true` because the entry existed, and verify-signer-key-grant then
 * reports it gone.
 */
export const RevokeSignerGrant = () =>
  fc
    .record({
      // Picks which live grant to revoke; `%` wraps onto the live set.
      grantIndex: fc.nat(),
    })
    .map((r) => {
      let revoked: string | undefined;
      const pickActiveGrant = (model: Readonly<Model>) =>
        model.activeGrants.size === 0
          ? undefined
          : Array.from(model.activeGrants)[
              r.grantIndex % model.activeGrants.size
            ];

      return {
        check: (model: Readonly<Model>) => pickActiveGrant(model) !== undefined,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'revoke-signer-grant');

          // Arrange
          const grant = pickActiveGrant(model)!;
          const { signerKey, signerManager } = parseGrantKey(grant);
          revoked = signerManager.split('.').pop();
          // Authorized caller is the principal derived from the signer key.
          const caller = signerAddress(signerKey);
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          // Model says the grant is live: it must verify before the revoke.
          const verifiedBefore = rovOk(
            real.contracts.pox5.verifySignerKeyGrant({
              signerManager,
              signerKey,
            }),
          );

          // Act
          const receipt = txOk(
            real.contracts.pox5.revokeSignerGrant({ signerManager, signerKey }),
            caller,
          );

          // Assert

          // Grant was live entering the command.
          expect(verifiedBefore).toBe(true);
          // Receipt tuple reports `existed: true` because the entry was live.
          expect(receipt.value.existed).toBe(true);
          // Grant is now gone: verify-signer-key-grant reports not-found.
          expect(
            rovErr(
              real.contracts.pox5.verifySignerKeyGrant({
                signerManager,
                signerKey,
              }),
            ),
          ).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);

          // Update model
          model.activeGrants.delete(grant);

          logCommand({
            action: 'revoke-signer-grant',
            value: revoked,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () => `revoke-signer-grant(${revoked ?? '?'})`,
      };
    });
