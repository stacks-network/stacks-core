import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  currentRewardCycle,
  getWalletNameByAddress,
  isStakerActive,
  logCommand,
  refreshModel,
  rewardCycleToBurnHeight,
  trackCommandRun,
} from './utils';
import { txOk } from '@clarigen/test';
import { expect } from 'vitest';

export const Stake = (accounts: Real['accounts']) =>
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
          model.signers.size > 0 && !isStakerActive(model, r.sender),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake');

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;

          const registered = Array.from(model.signers);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const expectedFirstStakedRewardCycle = currentRewardCycle(model) + 1n;
          const expectedUnlockCycle =
            expectedFirstStakedRewardCycle + BigInt(r.numCycles);
          const expectedUnlockBurnHeight =
            rewardCycleToBurnHeight(model, expectedUnlockCycle) +
            model.rewardCycleLength / 2n;

          const receipt = txOk(
            real.contracts.pox5.stake({
              signerManager: signer,
              amountUstx: r.amountUstx,
              numCycles: BigInt(r.numCycles),
              startBurnHt: real.network.burnBlockHeight,
              signerCalldata: null,
            }),
            r.sender,
          );

          expect(receipt.value.firstRewardCycle).toBe(
            expectedFirstStakedRewardCycle,
          );
          expect(receipt.value.unlockCycle).toBe(expectedUnlockCycle);
          expect(receipt.value.unlockBurnHeight).toBe(expectedUnlockBurnHeight);
          expect(receipt.value.signer).toBe(signer);
          expect(receipt.value.staker).toBe(r.sender);
          expect(receipt.value.amountUstx).toBe(r.amountUstx);

          model.stakers.set(r.sender, {
            amountUstx: r.amountUstx,
            firstRewardCycle: expectedFirstStakedRewardCycle,
            numCycles: BigInt(r.numCycles),
            unlockBurnHeight: expectedUnlockBurnHeight,
            unlockCycle: expectedUnlockCycle,
            signer,
          });

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake',
            value: `amount: ${r.amountUstx} cycles: ${r.numCycles} signer: ${signer}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake(${getWalletNameByAddress(r.sender)}, ${r.amountUstx}, ${r.numCycles}${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
