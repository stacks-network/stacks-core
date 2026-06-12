import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  parseUsedGrantKey,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { expect } from 'vitest';
import { errorCodes, testSignerHandle } from '../pox-5-helpers';

// grant-signer-key checks the used-grant map *before* recovering the
// signature, so on this rejected path the signature is never validated. A
// zero-filled (buff 65) is enough to reach the ERR_SIGNER_KEY_GRANT_USED
// branch.
const DUMMY_SIG = new Uint8Array(65);

/**
 * Replay a (signer-key, signer-manager, auth-id) tuple already consumed by an
 * earlier register/rotate. register-self's inner grant-signer-key rejects the
 * reused auth-id with ERR_SIGNER_KEY_GRANT_USED, which propagates out.
 * Requires model-aware generation: pure-random tuples would never collide in
 * the 1e9 auth-id space.
 */
export const RegisterSignerErrGrantUsed = (accounts: Real['accounts']) =>
  fc
    .record({
      caller: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Picks which consumed grant to replay; `%` wraps onto the live set.
      grantIndex: fc.nat(),
    })
    .map((r) => {
      let replayed: string | undefined;
      const pickUsedGrant = (model: Readonly<Model>) =>
        model.usedGrants.size === 0
          ? undefined
          : Array.from(model.usedGrants)[r.grantIndex % model.usedGrants.size];

      return {
        check: (model: Readonly<Model>) => pickUsedGrant(model) !== undefined,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-signer_err_grant_used');

          // Arrange

          // A tuple already in used-signer-key-grants.
          const { signerKey, signerManager, authId } = parseUsedGrantKey(
            pickUsedGrant(model)!,
          );
          replayed = `${signerManager.split('.').pop()}#${authId}`;
          const handle = testSignerHandle(signerManager);
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          // Every used grant came from a register/rotate, so the manager is
          // registered and its recorded key is the model's current key.
          const expectedKey = model.signers.get(signerManager)!.signerKey;
          const signerInfoBefore = rov(
            real.contracts.pox5.getSignerInfo(signerManager),
          );

          // Act
          const receipt = txErr(
            handle.registerSelf({
              signerManager,
              signerKey,
              authId,
              signerSig: DUMMY_SIG,
            }),
            r.caller,
          );

          // Assert

          // Pre-state: contract's recorded key matches the model.
          expect(signerInfoBefore).toEqual(expectedKey);
          // The reused auth-id is rejected before anything mutates.
          expect(receipt.value).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_USED);
          // The rejected call left the recorded key untouched.
          expect(rov(real.contracts.pox5.getSignerInfo(signerManager))).toEqual(
            signerInfoBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.caller),
            action: 'register-signer-err-grant-used',
            value: replayed,
            error: 'ERR_SIGNER_KEY_GRANT_USED',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-signer-err-grant-used(${getWalletNameByAddress(r.caller)}${replayed ? `, ${replayed}` : ''})`,
      };
    });
