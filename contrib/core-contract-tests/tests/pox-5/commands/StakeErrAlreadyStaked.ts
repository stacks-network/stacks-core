import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { expect } from 'vitest';
import { rov, txErr } from '@clarigen/test';
import { MAX_UINT128, errorCodes } from '../pox-5-helpers';

/**
 * Stake from a sender who is already staking. The already-staked check fails
 * with ERR_ALREADY_STAKED and mutates nothing.
 */
export const StakeErrAlreadyStaked = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Free over the full uint128 space; the balance check that would read it
      // sits past the already-staked check this targets.
      amountUstx: fc.bigInt({ min: 0n, max: MAX_UINT128 }),
      numCycles: fc.integer({ min: 1, max: 12 }),
      signerIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // Live grant and non-prepare-phase keep the earlier grant and
        // prepare-phase checks from masking ERR_ALREADY_STAKED.
        check: (model: Readonly<Model>) =>
          grantedSigners(model).length > 0 &&
          isStakerActive(model, r.sender) &&
          !isInPreparePhase(model),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake_err_already_staked');

          // Arrange
          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const expectedStaker = model.stakers.get(r.sender)!;
          const stakerInfoBefore = rov(
            real.contracts.pox5.getStakerInfo(r.sender),
          );

          // Act
          const receipt = txErr(
            real.contracts.pox5.stake({
              signerManager: signer,
              amountUstx: r.amountUstx,
              numCycles: BigInt(r.numCycles),
              startBurnHt: real.network.burnBlockHeight,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          // Pre-state matched the model's staker record.
          expect(stakerInfoBefore).toEqual({
            amountUstx: expectedStaker.amountUstx,
            firstRewardCycle: expectedStaker.firstRewardCycle,
            numCycles: expectedStaker.numCycles,
            signer: expectedStaker.signer,
          });
          expect(receipt.value).toBe(errorCodes.ERR_ALREADY_STAKED);
          // Rejected call left the staker record untouched.
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
            stakerInfoBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake-err-already-staked',
            error: 'ERR_ALREADY_STAKED',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake-err-already-staked(${getWalletNameByAddress(r.sender)}${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
