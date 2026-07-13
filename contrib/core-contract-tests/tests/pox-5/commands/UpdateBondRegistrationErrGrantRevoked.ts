import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  getWalletNameByAddress,
  isActiveBondMember,
  isInPreparePhase,
  logCommand,
  refreshModel,
  revokedSigners,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * update-bond-registration to a registered signer whose current grant was
 * revoked. The signer row exists, then grant verification rejects.
 */
export const UpdateBondRegistrationErrGrantRevoked = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        isActiveBondMember(model, r.sender) &&
        !isInPreparePhase(model) &&
        revokedSigners(model).includes(r.signer) &&
        r.signer !== model.bondMemberships.get(r.sender)!.signer,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const membership = model.bondMemberships.get(r.sender)!;
        const membershipBefore = rov(
          real.contracts.pox5.getBondMembership(r.sender),
        );
        const totalStakedBefore = rov(real.contracts.pox5.getTotalSbtcStaked());
        const balanceBefore = sbtcBalance(r.sender);

        // Act

        const receipt = txErr(
          real.contracts.pox5.updateBondRegistration({
            signerManager: r.signer,
            oldSignerManager: membership.signer,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(membershipBefore).toEqual(membership);
        expect(receipt.value).toBe(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
        expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
          membershipBefore,
        );
        expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
          totalStakedBefore,
        );
        expect(sbtcBalance(r.sender)).toBe(balanceBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'update-bond-registration-err-grant-revoked',
          error: 'ERR_SIGNER_KEY_GRANT_NOT_FOUND',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `update-bond-registration-err-grant-revoked(${getWalletNameByAddress(
          r.sender,
        )}, ${r.signer.split('.').pop()})`,
    }));
