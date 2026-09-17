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
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * stake-update extending beyond the contract's 96-cycle lock-period cap. The
 * grant and old-signer checks pass first, leaving ERR_INVALID_NUM_CYCLES.
 */
export const StakeUpdateErrInvalidNumCycles = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        !isInPreparePhase(model) &&
        isStakerActive(model, r.sender) &&
        grantedSigners(model).includes(r.signer),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const prev = model.stakers.get(r.sender)!;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const accountBefore = stxAccount(real, r.sender);
        // Any active stake has at most 95 future cycles left. Extending by 97
        // forces the internal stake-update num-cycles above the 96-cycle cap.
        const cyclesToExtend = 97n;

        // Act

        const receipt = txErr(
          real.contracts.pox5.stakeUpdate({
            signerManager: r.signer,
            oldSignerManager: prev.signer,
            cyclesToExtend,
            amountIncrease: 0n,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_INVALID_NUM_CYCLES);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );
        expect(stxAccount(real, r.sender)).toEqual(accountBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-update-err-invalid-num-cycles',
          value: cyclesToExtend,
          error: 'ERR_INVALID_NUM_CYCLES',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-update-err-invalid-num-cycles(${getWalletNameByAddress(
          r.sender,
        )})`,
    }));
