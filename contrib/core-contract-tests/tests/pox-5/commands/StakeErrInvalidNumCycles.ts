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
 * Stake with num-cycles outside the valid range. The num-cycles check fails
 * with ERR_INVALID_NUM_CYCLES and mutates nothing.
 */
export const StakeErrInvalidNumCycles = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Free over the full uint128 space; the balance check that would read it
      // sits past the num-cycles check this targets.
      amountUstx: fc.bigInt({ min: 0n, max: MAX_UINT128 }),
      // Pox-5 requires num-cycles in [1, 96]; draw from {0n} or [97n, ...] to
      // trip ERR_INVALID_NUM_CYCLES. The cap stays clear of MAX_UINT128
      // because the `let` computes `first-reward-cycle + num-cycles` before
      // any assert, and values near the max would hit Clarity's overflow path
      // instead.
      numCycles: fc.oneof(
        fc.constant(0n),
        fc.bigInt({ min: 97n, max: MAX_UINT128 - 100000n }),
      ),
      signerIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // Live grant, non-staking sender, and non-prepare-phase keep the
        // earlier checks from masking ERR_INVALID_NUM_CYCLES.
        check: (model: Readonly<Model>) =>
          grantedSigners(model).length > 0 &&
          !isStakerActive(model, r.sender) &&
          !isInPreparePhase(model),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake_err_invalid_num_cycles');

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

          // Pre-state confirms the sender was not staking.
          expect(stakerInfoBefore).toBeNull();
          expect(receipt.value).toBe(errorCodes.ERR_INVALID_NUM_CYCLES);
          // Rejected call left the staker record untouched.
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
            stakerInfoBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake-err-invalid-num-cycles',
            value: `numCycles: ${r.numCycles}`,
            error: 'ERR_INVALID_NUM_CYCLES',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake-err-invalid-num-cycles(${getWalletNameByAddress(r.sender)}, ${r.numCycles}${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
