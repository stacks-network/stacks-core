import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  logCommand,
  refreshModel,
  signerHasActiveGrant,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { deployer, errorCodes, pox5 } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Directly call register-signer from a wallet for a signer-manager that has a
 * live key grant. Grant verification passes first, then contract-caller is not
 * the signer contract and the call rejects with
 * ERR_UNAUTHORIZED_SIGNER_REGISTRATION.
 */
export const RegisterSignerErrUnauthorizedRegistration = () =>
  fc
    .record({
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) => signerHasActiveGrant(model, r.signer),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'register-signer_err_unauthorized');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const signerKey = model.signers.get(r.signer)!.signerKey;
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

        expect(signerInfoBefore).toEqual(signerKey);
        expect(receipt.value).toBe(
          errorCodes.ERR_UNAUTHORIZED_SIGNER_REGISTRATION,
        );
        expect(rov(pox5.getSignerInfo(r.signer))).toEqual(signerInfoBefore);

        logCommand({
          action: 'register-signer-err-unauthorized',
          value: r.signer,
          error: 'ERR_UNAUTHORIZED_SIGNER_REGISTRATION',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `register-signer-err-unauthorized(${r.signer.split('.').pop()})`,
    }));
