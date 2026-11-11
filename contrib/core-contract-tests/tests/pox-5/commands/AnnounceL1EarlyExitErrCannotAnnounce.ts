import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  isActiveBondMember,
  isInPreparePhase,
  logCommand,
  refreshModel,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * announce-l1-early-exit by a member whose bond is an sBTC lock, not an L1
 * lock. The is-l1-lock gate is the last assert, so passing the membership,
 * prepare-phase, and caller checks still lands on
 * ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK. Every bond in the suite registers via
 * the sBTC path, so `is-l1-lock` is always false. The L1-true side needs real
 * burn headers and lives in the stacks-node integration tests.
 */
export const AnnounceL1EarlyExitErrCannotAnnounce = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      staker: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      // An active sBTC member outside the prepare phase, announcing for itself,
      // so the only check left to fail is the L1-lock gate.
      check: (model: Readonly<Model>) => {
        const membership = model.bondMemberships.get(r.staker);
        return (
          !isInPreparePhase(model) &&
          isActiveBondMember(model, r.staker) &&
          membership !== undefined &&
          !membership.isL1Lock
        );
      },
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

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

        expect(receipt.value).toBe(
          errorCodes.eRR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK,
        );
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
          action: 'announce-l1-early-exit-err-cannot-announce',
          error: 'ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `announce-l1-early-exit-err-cannot-announce(${getWalletNameByAddress(
          r.staker,
        )})`,
    }));
