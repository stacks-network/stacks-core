import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  grantedSigners,
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
 * Update a bond registration passing a wrong `old-signer-manager`. The
 * membership resolves and the call is outside the prepare phase, so the
 * `(is-eq old-signer current-signer)` assert is the gate: it reverts with
 * ERR_INVALID_OLD_SIGNER_MANAGER before the same-signer check and mutates
 * nothing.
 */
export const UpdateBondRegistrationErrInvalidOldSignerManager = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      wrongIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // An active bond member outside the prepare phase, plus a granted
        // signer other than the member's current one to pass as the wrong old
        // signer, leaves the old-signer assert as the only revert reason.
        check: (model: Readonly<Model>) =>
          isActiveBondMember(model, r.sender) &&
          !isInPreparePhase(model) &&
          grantedSigners(model).some(
            (s) => s !== model.bondMemberships.get(r.sender)!.signer,
          ),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(
            model,
            'update-bond-registration_err_invalid_old_signer',
          );

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const membership = model.bondMemberships.get(r.sender)!;
          const currentSigner = membership.signer;
          const wrongCandidates = grantedSigners(model).filter(
            (s) => s !== currentSigner,
          );
          const wrongSigner =
            wrongCandidates[r.wrongIndex % wrongCandidates.length];
          pickedSigner = wrongSigner;
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.sender),
          );
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );
          const balanceBefore = sbtcBalance(r.sender);

          // Act

          // New signer is the correct current one; only old is wrong, so the
          // same-signer check (new == old) cannot pre-empt the old-signer one.
          const receipt = txErr(
            real.contracts.pox5.updateBondRegistration({
              signerManager: currentSigner,
              oldSignerManager: wrongSigner,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          // Pre-state matched the model: membership present and unchanged.
          expect(membershipBefore).toEqual(membership);
          expect(receipt.value).toBe(errorCodes.ERR_INVALID_OLD_SIGNER_MANAGER);
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
            action: 'update-bond-registration-err-invalid-old-signer',
            error: 'ERR_INVALID_OLD_SIGNER_MANAGER',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `update-bond-registration-err-invalid-old-signer(${getWalletNameByAddress(
            r.sender,
          )}${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
