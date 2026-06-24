import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  refreshModel,
  revokedSigners,
  stxAccount,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * stake-update to a registered signer whose current grant was revoked. The
 * signer row exists, then verify-signer-key-grant reports not-found.
 */
export const StakeUpdateErrGrantRevoked = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
      cyclesToExtend: fc.bigInt({ min: 0n, max: 12n }),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) => {
        if (isInPreparePhase(model)) return false;
        if (!isStakerActive(model, r.sender)) return false;
        if (!revokedSigners(model).includes(r.signer)) return false;
        const prev = model.stakers.get(r.sender)!;
        const internalNumCycles =
          prev.firstRewardCycle +
          prev.numCycles +
          r.cyclesToExtend -
          currentRewardCycle(model) -
          1n;
        return internalNumCycles >= 1n && internalNumCycles <= 96n;
      },
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const prev = model.stakers.get(r.sender)!;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const accountBefore = stxAccount(real, r.sender);

        // Act

        const receipt = txErr(
          real.contracts.pox5.stakeUpdate({
            signerManager: r.signer,
            oldSignerManager: prev.signer,
            cyclesToExtend: r.cyclesToExtend,
            amountIncrease: 0n,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );
        expect(stxAccount(real, r.sender)).toEqual(accountBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-update-err-grant-revoked',
          error: 'ERR_SIGNER_KEY_GRANT_NOT_FOUND',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-update-err-grant-revoked(${getWalletNameByAddress(
          r.sender,
        )}, ${r.signer.split('.').pop()})`,
    }));
