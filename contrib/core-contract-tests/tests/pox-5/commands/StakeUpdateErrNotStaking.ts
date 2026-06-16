import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  getWalletNameByAddress,
  isStakerActive,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * stake-update loads current staker-info before phase, signer, and caller
 * checks. A sender with no active row is rejected with ERR_NOT_STAKING.
 */
export const StakeUpdateErrNotStaking = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
      oldSigner: fc.constantFrom(...candidateSignerIds),
      cyclesToExtend: fc.bigInt({ min: 0n, max: 96n }),
      amountIncrease: fc.bigInt({ min: 0n, max: 1_000_000_000_000n }),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        model.deployedSigners.has(r.signer) &&
        model.deployedSigners.has(r.oldSigner) &&
        !isStakerActive(model, r.sender),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'stake-update_err_not_staking');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );

        // Act

        const receipt = txErr(
          real.contracts.pox5.stakeUpdate({
            signerManager: r.signer,
            oldSignerManager: r.oldSigner,
            cyclesToExtend: r.cyclesToExtend,
            amountIncrease: r.amountIncrease,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(stakerInfoBefore).toBeNull();
        expect(receipt.value).toBe(errorCodes.ERR_NOT_STAKING);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-update-err-not-staking',
          error: 'ERR_NOT_STAKING',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-update-err-not-staking(${getWalletNameByAddress(r.sender)})`,
    }));
