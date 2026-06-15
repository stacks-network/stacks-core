import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  isActiveBondMember,
  isInPreparePhase,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * announce-l1-early-exit during the prepare phase. The prepare-phase guard
 * runs right after the membership lookup, before the caller and L1-lock
 * checks, so a member announcing here reverts with ERR_STAKE_IN_PREPARE_PHASE
 * and mutates nothing.
 */
export const AnnounceL1EarlyExitErrInPreparePhase = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      staker: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      // An active member, in the prepare phase.
      check: (model: Readonly<Model>) =>
        isInPreparePhase(model) && isActiveBondMember(model, r.staker),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'announce-l1-early-exit_err_in_prepare_phase');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const membership = model.bondMemberships.get(r.staker)!;
        const membershipBefore = rov(
          real.contracts.pox5.getBondMembership(r.staker),
        );
        const totalStakedBefore = rov(
          real.contracts.pox5.getTotalSbtcStakedForBond(membership.bondIndex),
        );

        // Act

        const receipt = txErr(
          real.contracts.pox5.announceL1EarlyExit(r.staker, membership.signer),
          r.staker,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_STAKE_IN_PREPARE_PHASE);
        expect(rov(real.contracts.pox5.getBondMembership(r.staker))).toEqual(
          membershipBefore,
        );
        expect(
          rov(
            real.contracts.pox5.getTotalSbtcStakedForBond(membership.bondIndex),
          ),
        ).toBe(totalStakedBefore);

        logCommand({
          sender: getWalletNameByAddress(r.staker),
          action: 'announce-l1-early-exit-err-in-prepare-phase',
          error: 'ERR_STAKE_IN_PREPARE_PHASE',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `announce-l1-early-exit-err-in-prepare-phase(${getWalletNameByAddress(
          r.staker,
        )})`,
    }));
