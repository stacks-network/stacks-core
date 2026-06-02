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

export const StakeErrInvalidNumCycles = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // amount-ustx is read only on the (last) balance check; on the
      // ERR_INVALID_NUM_CYCLES branch it never influences the outcome, so
      // leave the full uint128 space open.
      amountUstx: fc.bigInt({ min: 0n, max: MAX_UINT128 }),
      // Pox-5 requires num-cycles ∈ [1, 96]. Generate from {0n} ∪ [97n, ...]
      // so the targeted ERR_INVALID_NUM_CYCLES branch fires. The upper cap
      // stays clear of MAX_UINT128 because the contract evaluates
      //   `unlock-cycle = first-reward-cycle + num-cycles`
      // in the `let` binding before any assert; values near MAX_UINT128 would
      // trip Clarity's runtime arithmetic-overflow path, which is the VM's
      // concern and outside pox-5's domain.
      numCycles: fc.oneof(
        fc.constant(0n),
        fc.bigInt({ min: 97n, max: MAX_UINT128 - 100000n }),
      ),
      signerIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // Gate on the same preconditions as Stake so we know ERR_INVALID_NUM_CYCLES
        // is the *first* failing assertion: registered signer exists, sender
        // not yet staking (otherwise the contract path is identical until the
        // num-cycles check, which fires before the already-staked check anyway).
        check: (model: Readonly<Model>) =>
          model.signers.size > 0 && !isStakerActive(model, r.sender),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake_err_invalid_num_cycles');

          // Arrange
          const registered = Array.from(model.signers);
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

          // Model predicted sender was not staking; contract should agree.
          expect(stakerInfoBefore).toBeNull();
          // Contract rejected with the num-cycles error.
          expect(receipt.value).toBe(errorCodes.ERR_INVALID_NUM_CYCLES);
          // No partial mutation of staker state.
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
