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
import { txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';

export const StakeErrAlreadyStaked = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      amountUstx: fc.bigInt({ min: 1000000n, max: 10000000n }),
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

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;

        const registered = Array.from(model.signers);
        const signer = registered[r.signerIndex % registered.length];
        pickedSigner = signer;

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

        expect(receipt.value).toBe(errorCodes.ERR_ALREADY_STAKED);

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
