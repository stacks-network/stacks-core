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
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Update a bond registration to the same signer it already has. The membership
 * resolves, the call is outside the prepare phase, and the old signer is the
 * correct current one, so the `(not (is-eq signer old-signer))` assert is the
 * gate: it reverts with ERR_UPDATE_BOND_SAME_SIGNER and mutates nothing.
 */
export const UpdateBondRegistrationErrUpdateBondSameSigner = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => {
      return {
        // An active bond member outside the prepare phase, passing its own
        // signer as both old and new, leaves the same-signer assert as the
        // only revert reason (old == current passes the prior check).
        check: (model: Readonly<Model>) =>
          isActiveBondMember(model, r.sender) && !isInPreparePhase(model),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'update-bond-registration_err_same_signer');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const membership = model.bondMemberships.get(r.sender)!;
          const currentSigner = membership.signer;
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.sender),
          );
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );
          const balanceBefore = sbtcBalance(r.sender);

          // Act

          // Old == new == the current signer: the old-signer check passes, so
          // the same-signer check is the one that trips.
          const receipt = txErr(
            real.contracts.pox5.updateBondRegistration({
              signerManager: currentSigner,
              oldSignerManager: currentSigner,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          // Pre-state matched the model: membership present and unchanged.
          expect(membershipBefore).toEqual(membership);
          expect(receipt.value).toBe(errorCodes.ERR_UPDATE_BOND_SAME_SIGNER);
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
            action: 'update-bond-registration-err-same-signer',
            error: 'ERR_UPDATE_BOND_SAME_SIGNER',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `update-bond-registration-err-same-signer(${getWalletNameByAddress(
            r.sender,
          )})`,
      };
    });
