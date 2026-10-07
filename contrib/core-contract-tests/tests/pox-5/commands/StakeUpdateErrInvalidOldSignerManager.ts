import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  refreshModel,
  stxAccount,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * stake-update with a wrong old signer-manager. The new signer validates and
 * the internal cycle count stays in range, so the old-signer assertion is the
 * targeted rejection.
 */
export const StakeUpdateErrInvalidOldSignerManager = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
      wrongOldSigner: fc.constantFrom(...candidateSignerIds),
      cyclesToExtend: fc.bigInt({ min: 0n, max: 12n }),
      amountIncrease: fc.bigInt({ min: 0n, max: 1_000_000_000_000n }),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) => {
        if (isInPreparePhase(model)) return false;
        if (!isStakerActive(model, r.sender)) return false;
        if (!grantedSigners(model).includes(r.signer)) return false;
        if (!model.deployedSigners.has(r.wrongOldSigner)) return false;
        const prev = model.stakers.get(r.sender)!;
        if (r.wrongOldSigner === prev.signer) return false;
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
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const accountBefore = stxAccount(real, r.sender);

        // Act

        const receipt = txErr(
          real.contracts.pox5.stakeUpdate({
            signerManager: r.signer,
            oldSignerManager: r.wrongOldSigner,
            cyclesToExtend: r.cyclesToExtend,
            amountIncrease: r.amountIncrease,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_INVALID_OLD_SIGNER_MANAGER);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );
        expect(stxAccount(real, r.sender)).toEqual(accountBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-update-err-invalid-old-signer',
          error: 'ERR_INVALID_OLD_SIGNER_MANAGER',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-update-err-invalid-old-signer(${getWalletNameByAddress(
          r.sender,
        )}, ${r.wrongOldSigner.split('.').pop()})`,
    }));
