import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  refreshModel,
  revokedSigners,
  trackCommandRun,
} from './utils';
import { expect } from 'vitest';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';

/**
 * Stake with a registered signer whose grant has been revoked. Every new-stake
 * entry point re-checks the grant (`verify-signer-key-grant`), so the stake
 * reverts with ERR_SIGNER_KEY_GRANT_NOT_FOUND and mutates nothing.
 */
export const StakeErrGrantRevoked = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      amountUstx: fc.bigInt({ min: 1000000n, max: 1000000000000n }),
      numCycles: fc.bigInt({ min: 1n, max: 96n }),
      signerIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // Need a registered-but-revoked signer; sender not already staking; not
        // in the prepare phase (its guard runs first).
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          !isStakerActive(model, r.sender) &&
          revokedSigners(model).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake_err_grant_revoked');

          // Arrange

          const revoked = revokedSigners(model);
          const signer = revoked[r.signerIndex % revoked.length];
          pickedSigner = signer;
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const stakerInfoBefore = rov(
            real.contracts.pox5.getStakerInfo(r.sender),
          );

          // Act

          const receipt = txErr(
            real.contracts.pox5.stake({
              signerManager: signer,
              amountUstx: r.amountUstx,
              numCycles: r.numCycles,
              startBurnHt: real.network.burnBlockHeight,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          expect(stakerInfoBefore).toBeNull();
          expect(receipt.value).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
          // Rejected call left the staker record untouched.
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
            stakerInfoBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake-err-grant-revoked',
            value: signer.split('.').pop(),
            error: 'ERR_SIGNER_KEY_GRANT_NOT_FOUND',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake-err-grant-revoked(${getWalletNameByAddress(r.sender)}${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
