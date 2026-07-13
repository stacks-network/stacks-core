import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  getWalletNameByAddress,
  isInPreparePhase,
  logCommand,
  refreshModel,
} from './utils';
import { expect } from 'vitest';
import { rov, txErr } from '@clarigen/test';
import { MAX_UINT128, errorCodes } from '../pox-5-helpers';

/**
 * Stake naming a deployed-but-unregistered signer-manager. The signer lookup
 * fails with ERR_SIGNER_NOT_FOUND and mutates nothing.
 */
export const StakeErrSignerNotFound = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Free over the full uint128 space; the balance check that would read it
      // sits past the signer lookup this targets.
      amountUstx: fc.bigInt({ min: 0n, max: MAX_UINT128 }),
      numCycles: fc.integer({ min: 1, max: 12 }),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => {
      return {
        // Non-prepare-phase keeps the earlier prepare-phase guard from masking
        // ERR_SIGNER_NOT_FOUND. The signer must be deployed but unregistered.
        check: (model: Readonly<Model>) =>
          model.deployedSigners.has(r.signer) &&
          !model.signers.has(r.signer) &&
          !isInPreparePhase(model),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);

          // Arrange
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const stakerInfoBefore = rov(
            real.contracts.pox5.getStakerInfo(r.sender),
          );

          // Act
          const receipt = txErr(
            real.contracts.pox5.stake({
              signerManager: r.signer,
              amountUstx: r.amountUstx,
              numCycles: BigInt(r.numCycles),
              startBurnHt: real.network.burnBlockHeight,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert
          expect(receipt.value).toBe(errorCodes.ERR_SIGNER_NOT_FOUND);
          // Rejected call left the staker record untouched.
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
            stakerInfoBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake-err-signer-not-found',
            error: 'ERR_SIGNER_NOT_FOUND',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake-err-signer-not-found(${getWalletNameByAddress(r.sender)}, ${r.signer.split('.').pop()})`,
      };
    });
