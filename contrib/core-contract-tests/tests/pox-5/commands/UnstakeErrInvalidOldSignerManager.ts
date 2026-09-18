import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  getWalletNameByAddress,
  isStakerActive,
  logCommand,
  refreshModel,
  stxAccount,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * unstake with an old signer-manager that does not match the staker's current
 * signer. This guard runs before prepare-phase checks and mutates nothing.
 */
export const UnstakeErrInvalidOldSignerManager = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      wrongSigner: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        isStakerActive(model, r.sender) &&
        model.deployedSigners.has(r.wrongSigner) &&
        r.wrongSigner !== model.stakers.get(r.sender)!.signer,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const accountBefore = stxAccount(real, r.sender);

        // Act

        const receipt = txErr(
          real.contracts.pox5.unstake({ oldSignerManager: r.wrongSigner }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_INVALID_OLD_SIGNER_MANAGER);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );
        expect(stxAccount(real, r.sender)).toEqual(accountBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'unstake-err-invalid-old-signer',
          error: 'ERR_INVALID_OLD_SIGNER_MANAGER',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `unstake-err-invalid-old-signer(${getWalletNameByAddress(
          r.sender,
        )}, ${r.wrongSigner.split('.').pop()})`,
    }));
