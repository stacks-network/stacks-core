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
 * announce-l1-early-exit for a real member, but sent by someone else. Only the
 * staker may announce their own exit (contract-caller must equal the staker),
 * so a foreign caller reverts with ERR_UNAUTHORIZED and mutates nothing.
 */
export const AnnounceL1EarlyExitErrUnauthorized = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      staker: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      caller: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      // An active member outside the prepare phase (so the caller check trips,
      // not the prepare-phase guard before it), announced by a foreign caller.
      check: (model: Readonly<Model>) =>
        !isInPreparePhase(model) &&
        isActiveBondMember(model, r.staker) &&
        r.caller !== r.staker,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'announce-l1-early-exit_err_unauthorized');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const membership = model.bondMemberships.get(r.staker)!;
        const membershipBefore = rov(
          real.contracts.pox5.getBondMembership(r.staker),
        );

        // Act

        const receipt = txErr(
          real.contracts.pox5.announceL1EarlyExit(r.staker, membership.signer),
          r.caller,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_UNAUTHORIZED);
        expect(rov(real.contracts.pox5.getBondMembership(r.staker))).toEqual(
          membershipBefore,
        );

        logCommand({
          sender: getWalletNameByAddress(r.caller),
          action: 'announce-l1-early-exit-err-unauthorized',
          value: `for ${getWalletNameByAddress(r.staker)}`,
          error: 'ERR_UNAUTHORIZED',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `announce-l1-early-exit-err-unauthorized(${getWalletNameByAddress(
          r.staker,
        )})`,
    }));
