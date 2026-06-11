import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { expect } from 'vitest';
import { errorCodes } from '../pox-5-helpers';

/**
 * Unstake during the prepare phase. With an active staker, the prepare-phase
 * guard fails with ERR_UNSTAKE_IN_PREPARE_PHASE and mutates nothing.
 */
export const UnstakeErrInPreparePhase = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      // Active staker in the prepare phase: the guard is the only reason
      // unstake reverts.
      check: (model: Readonly<Model>) =>
        isStakerActive(model, r.sender) && isInPreparePhase(model),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'unstake_err_in_prepare_phase');

        // Arrange
        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const prev = model.stakers.get(r.sender)!;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );

        // Act
        const receipt = txErr(
          real.contracts.pox5.unstake({ oldSignerManager: prev.signer }),
          r.sender,
        );

        // Assert

        // Pre-state matched the model's staker record.
        expect(stakerInfoBefore).toEqual({
          amountUstx: prev.amountUstx,
          firstRewardCycle: prev.firstRewardCycle,
          numCycles: prev.numCycles,
          signer: prev.signer,
        });
        // Within `prepareCycleLength` of the cycle end, so unstake is blocked.
        expect(receipt.value).toBe(errorCodes.ERR_UNSTAKE_IN_PREPARE_PHASE);
        // Rejected call left the staker record untouched.
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'unstake-err-in-prepare-phase',
          error: 'ERR_UNSTAKE_IN_PREPARE_PHASE',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `unstake-err-in-prepare-phase(${getWalletNameByAddress(r.sender)})`,
    }));
