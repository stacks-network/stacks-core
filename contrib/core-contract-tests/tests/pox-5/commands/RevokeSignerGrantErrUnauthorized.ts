import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  parseGrantKey,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rovOk, txErr } from '@clarigen/test';
import { expect } from 'vitest';
import { errorCodes } from '../pox-5-helpers';

/**
 * Attempt to revoke a live grant from the wrong sender. revoke-signer-grant
 * checks `tx-sender == principal(hash160(signer-key))` first, so any other
 * caller is rejected with ERR_UNAUTHORIZED and the grant survives untouched.
 */
export const RevokeSignerGrantErrUnauthorized = (accounts: Real['accounts']) =>
  fc
    .record({
      // The unauthorized caller (a wallet address). The authorized caller is
      // the key's derived principal (hash160 of a random signer pubkey), which
      // is never equal to a Devnet.toml fixed wallet, so this is always the
      // wrong sender.
      caller: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Picks which live grant to target; `%` wraps onto the live set.
      grantIndex: fc.nat(),
    })
    .map((r) => {
      let target: string | undefined;
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
          trackCommandRun(model, 'revoke-signer-grant_err_unauthorized');

          // Arrange
          const grant = pickActiveGrant(model)!;
          const { signerKey, signerManager } = parseGrantKey(grant);
          target = signerManager.split('.').pop();
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          // Model says this grant is live. It must verify before the call.
          const verifiedBefore = rovOk(
            real.contracts.pox5.verifySignerKeyGrant({
              signerManager,
              signerKey,
            }),
          );

          // Act
          const receipt = txErr(
            real.contracts.pox5.revokeSignerGrant({ signerManager, signerKey }),
            r.caller,
          );

          // Assert

          // Grant was live entering the command.
          expect(verifiedBefore).toBe(true);
          // Rejected on the authorization check.
          expect(receipt.value).toBe(errorCodes.ERR_UNAUTHORIZED);
          // No mutation: the grant is still live afterwards.
          expect(
            rovOk(
              real.contracts.pox5.verifySignerKeyGrant({
                signerManager,
                signerKey,
              }),
            ),
          ).toBe(true);

          logCommand({
            sender: getWalletNameByAddress(r.caller),
            action: 'revoke-signer-grant-err-unauthorized',
            value: target,
            error: 'ERR_UNAUTHORIZED',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `revoke-signer-grant-err-unauthorized(${getWalletNameByAddress(r.caller)}${target ? `, ${target}` : ''})`,
      };
    });
