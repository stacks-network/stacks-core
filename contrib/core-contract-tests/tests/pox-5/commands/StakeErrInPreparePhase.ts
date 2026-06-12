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
import { errorCodes } from '../pox-5-helpers';

/**
 * Stake during the prepare phase. `verify-not-prepare-phase` is the first check
 * in `stake`, so an otherwise-valid stake (granted signer, non-staking sender,
 * valid amount/num-cycles) reverts with ERR_STAKE_IN_PREPARE_PHASE and mutates
 * nothing.
 */
export const StakeErrInPreparePhase = (accounts: Real['accounts']) =>
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
        // Granted signer and non-staking sender leave the prepare-phase guard
        // as the only reason the stake reverts.
        check: (model: Readonly<Model>) =>
          isInPreparePhase(model) &&
          grantedSigners(model).length > 0 &&
          !isStakerActive(model, r.sender),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake_err_in_prepare_phase');

          // Arrange

          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
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
          expect(receipt.value).toBe(errorCodes.ERR_STAKE_IN_PREPARE_PHASE);
          // Rejected call left the staker record untouched.
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
            stakerInfoBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake-err-in-prepare-phase',
            error: 'ERR_STAKE_IN_PREPARE_PHASE',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake-err-in-prepare-phase(${getWalletNameByAddress(r.sender)}${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
