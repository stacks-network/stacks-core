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
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { TOTAL_LIQUID_SUPPLY_USTX, errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * stake-update asks to increase the locked STX by more than the caller's
 * unlocked account balance. All prior checks pass, so ERR_INSUFFICIENT_STX is
 * the rejection and no lock metadata changes.
 */
export const StakeUpdateErrInsufficientStx = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) => {
        if (isInPreparePhase(model)) return false;
        if (!isStakerActive(model, r.sender)) return false;
        if (!grantedSigners(model).includes(r.signer)) return false;
        const prev = model.stakers.get(r.sender)!;
        const internalNumCycles =
          prev.firstRewardCycle +
          prev.numCycles -
          currentRewardCycle(model) -
          1n;
        return internalNumCycles >= 1n && internalNumCycles <= 96n;
      },
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'stake-update_err_insufficient_stx');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const prev = model.stakers.get(r.sender)!;
        const amountIncrease = TOTAL_LIQUID_SUPPLY_USTX;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const accountBefore = stxAccount(real, r.sender);

        // Act

        const receipt = txErr(
          real.contracts.pox5.stakeUpdate({
            signerManager: r.signer,
            oldSignerManager: prev.signer,
            cyclesToExtend: 0n,
            amountIncrease,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_INSUFFICIENT_STX);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );
        expect(stxAccount(real, r.sender)).toEqual(accountBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-update-err-insufficient-stx',
          value: amountIncrease,
          error: 'ERR_INSUFFICIENT_STX',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-update-err-insufficient-stx(${getWalletNameByAddress(
          r.sender,
        )})`,
    }));
