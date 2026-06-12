import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  grantedSigners,
  isActiveBondMember,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Update a bond registration for a sender who is not an active bond
 * participant. The `get-bond-membership` unwrap is the first step of the `let`,
 * so it reverts with ERR_NOT_BOND_PARTICIPANT before any later check and
 * mutates nothing.
 */
export const UpdateBondRegistrationErrNotBondParticipant = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      oldIndex: fc.nat(),
      newIndex: fc.nat(),
    })
    .map((r) => {
      return {
        // A non-member sender makes the membership unwrap the first failure. A
        // granted signer keeps the old/new trait handles well formed.
        check: (model: Readonly<Model>) =>
          grantedSigners(model).length > 0 &&
          !isActiveBondMember(model, r.sender),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(
            model,
            'update-bond-registration_err_not_bond_participant',
          );

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const registered = grantedSigners(model);
          const oldSigner = registered[r.oldIndex % registered.length];
          const newSigner = registered[r.newIndex % registered.length];
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.sender),
          );
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );
          const balanceBefore = sbtcBalance(r.sender);

          // Act

          const receipt = txErr(
            real.contracts.pox5.updateBondRegistration({
              signerManager: newSigner,
              oldSignerManager: oldSigner,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          // Pre-state matched the model: no membership.
          expect(membershipBefore).toBeNull();
          expect(receipt.value).toBe(errorCodes.ERR_NOT_BOND_PARTICIPANT);
          // Rejected call left membership and sBTC custody untouched.
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            membershipBefore,
          );
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalStakedBefore,
          );
          expect(sbtcBalance(r.sender)).toBe(balanceBefore);

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'update-bond-registration-err-not-bond-participant',
            error: 'ERR_NOT_BOND_PARTICIPANT',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `update-bond-registration-err-not-bond-participant(${getWalletNameByAddress(
            r.sender,
          )})`,
      };
    });
