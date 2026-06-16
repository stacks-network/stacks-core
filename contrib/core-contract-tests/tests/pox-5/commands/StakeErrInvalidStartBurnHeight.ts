import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { MAX_UINT128, errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Stake with a start burn height that resolves past the next reward cycle.
 * Signer validation and grant verification pass first, so the start-height
 * assertion is the targeted rejection and no staker row is written.
 */
export const StakeErrInvalidStartBurnHeight = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      amountUstx: fc.bigInt({ min: 0n, max: MAX_UINT128 }),
      numCycles: fc.bigInt({ min: 1n, max: 96n }),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        !isInPreparePhase(model) && grantedSigners(model).includes(r.signer),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'stake_err_invalid_start_burn_height');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const futureStartBurnHeight =
          model.burnBlockHeight + model.rewardCycleLength;

        // Act

        const receipt = txErr(
          real.contracts.pox5.stake({
            signerManager: r.signer,
            amountUstx: r.amountUstx,
            numCycles: r.numCycles,
            startBurnHt: futureStartBurnHeight,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_INVALID_START_BURN_HEIGHT);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-err-invalid-start-burn-height',
          error: 'ERR_INVALID_START_BURN_HEIGHT',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-err-invalid-start-burn-height(${getWalletNameByAddress(
          r.sender,
        )}, ${r.signer.split('.').pop()})`,
    }));
