import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  isStakerActive,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { expect } from 'vitest';
import { rov, txErr } from '@clarigen/test';
import { MAX_UINT128, errorCodes } from '../pox-5-helpers';

export const StakeErrAlreadyStaked = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // amount-ustx is irrelevant once ERR_ALREADY_STAKED fires; the
      // balance check is the last assert in the chain.
      amountUstx: fc.bigInt({ min: 0n, max: MAX_UINT128 }),
      numCycles: fc.integer({ min: 1, max: 12 }),
      signerIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        check: (model: Readonly<Model>) =>
          model.signers.size > 0 && isStakerActive(model, r.sender),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake_err_already_staked');

          // Arrange
          const registered = Array.from(model.signers.keys());
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

          // Model says sender is already staking; contract should agree and
          // its view should match the model's recorded staker.
          expect(stakerInfoBefore).toEqual({
            amountUstx: expectedStaker.amountUstx,
            firstRewardCycle: expectedStaker.firstRewardCycle,
            numCycles: expectedStaker.numCycles,
            signer: expectedStaker.signer,
          });
          // Contract rejected with the expected error code.
          expect(receipt.value).toBe(errorCodes.ERR_ALREADY_STAKED);
          // Failing call did not mutate the sender's staker record.
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
