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
 * unstake loads current staker-info before old-signer and prepare-phase
 * checks. A sender with no active row is rejected with ERR_NOT_STAKING.
 */
export const UnstakeErrNotStaking = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        model.deployedSigners.has(r.signer) && !isStakerActive(model, r.sender),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'unstake_err_not_staking');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );

        // Act

        const receipt = txErr(
          real.contracts.pox5.unstake({ oldSignerManager: r.signer }),
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
          action: 'unstake-err-not-staking',
          error: 'ERR_NOT_STAKING',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `unstake-err-not-staking(${getWalletNameByAddress(r.sender)})`,
    }));
