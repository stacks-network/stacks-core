import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
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
 * Stake more STX than any single simnet account can own. Earlier guards are
 * kept satisfied, so the total-balance check rejects with ERR_INSUFFICIENT_STX.
 */
export const StakeErrInsufficientStx = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      numCycles: fc.bigInt({ min: 1n, max: 96n }),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        !isInPreparePhase(model) &&
        grantedSigners(model).includes(r.signer) &&
        !isStakerActive(model, r.sender) &&
        !model.bondMemberships.has(r.sender),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'stake_err_insufficient_stx');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const amountUstx = TOTAL_LIQUID_SUPPLY_USTX + 1n;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const accountBefore = stxAccount(real, r.sender);

        // Act

        const receipt = txErr(
          real.contracts.pox5.stake({
            signerManager: r.signer,
            amountUstx,
            numCycles: r.numCycles,
            startBurnHt: real.network.burnBlockHeight,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(stakerInfoBefore).toBeNull();
        expect(receipt.value).toBe(errorCodes.ERR_INSUFFICIENT_STX);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );
        expect(stxAccount(real, r.sender)).toEqual(accountBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-err-insufficient-stx',
          value: amountUstx,
          error: 'ERR_INSUFFICIENT_STX',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-err-insufficient-stx(${getWalletNameByAddress(
          r.sender,
        )}, ${r.signer.split('.').pop()})`,
    }));
