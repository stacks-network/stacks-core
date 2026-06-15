import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, testSigner } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * announce-l1-early-exit for a principal that holds no bond membership. The
 * membership unwrap is the first thing the call does, so it reverts with
 * ERR_NOT_BOND_PARTICIPANT and mutates nothing.
 */
export const AnnounceL1EarlyExitErrNotBondParticipant = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      staker: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      // The generated principal must hold no membership.
      check: (model: Readonly<Model>) => !model.bondMemberships.has(r.staker),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(
          model,
          'announce-l1-early-exit_err_not_bond_participant',
        );

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;

        // Act

        const receipt = txErr(
          real.contracts.pox5.announceL1EarlyExit(
            r.staker,
            testSigner.identifier,
          ),
          r.staker,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_NOT_BOND_PARTICIPANT);
        // No membership existed and none was created.
        expect(rov(real.contracts.pox5.getBondMembership(r.staker))).toBeNull();

        logCommand({
          sender: getWalletNameByAddress(r.staker),
          action: 'announce-l1-early-exit-err-not-bond-participant',
          error: 'ERR_NOT_BOND_PARTICIPANT',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `announce-l1-early-exit-err-not-bond-participant(${getWalletNameByAddress(
          r.staker,
        )})`,
    }));
