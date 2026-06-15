import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
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
 * Update a bond registration during the prepare phase. The membership unwrap
 * resolves (the sender is an active member), so `verify-not-prepare-phase` is
 * the first guard to fire: the call reverts with ERR_STAKE_IN_PREPARE_PHASE
 * before the old/new signer checks and mutates nothing.
 */
export const UpdateBondRegistrationErrInPreparePhase = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => {
      return {
        // An active bond member in the prepare phase leaves the prepare-phase
        // guard as the only revert reason. A granted signer keeps the new
        // trait handle well formed; the old one is the correct current signer.
        check: (model: Readonly<Model>) =>
          isActiveBondMember(model, r.sender) &&
          isInPreparePhase(model) &&
          grantedSigners(model).includes(r.signer),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(
            model,
            'update-bond-registration_err_in_prepare_phase',
          );

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const membership = model.bondMemberships.get(r.sender)!;
          const oldSigner = membership.signer;
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
              signerManager: r.signer,
              oldSignerManager: oldSigner,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          // Pre-state matched the model: membership present and unchanged.
          expect(membershipBefore).toEqual(membership);
          expect(receipt.value).toBe(errorCodes.ERR_STAKE_IN_PREPARE_PHASE);
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
            action: 'update-bond-registration-err-in-prepare-phase',
            error: 'ERR_STAKE_IN_PREPARE_PHASE',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `update-bond-registration-err-in-prepare-phase(${getWalletNameByAddress(
            r.sender,
          )}, ${r.signer.split('.').pop()})`,
      };
    });
