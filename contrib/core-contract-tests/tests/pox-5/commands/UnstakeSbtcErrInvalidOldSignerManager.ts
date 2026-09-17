import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  getWalletNameByAddress,
  isActiveBondMember,
  isInPreparePhase,
  logCommand,
  refreshModel,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * unstake-sbtc passing a signer-manager that is not the member's current
 * signer. With a valid amount and outside the prepare phase, the signer-match
 * assert is the gate that trips, so the call reverts with
 * ERR_INVALID_OLD_SIGNER_MANAGER and mutates nothing.
 */
export const UnstakeSbtcErrInvalidOldSignerManager = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      withdrawalBips: fc.bigInt({ min: 1n, max: 10000n }),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        // An active member outside the prepare phase, with sats to withdraw and
        // a deployed signer other than their own to pass as the wrong one.
        check: (model: Readonly<Model>) => {
          const membership = model.bondMemberships.get(r.sender);
          return (
            isActiveBondMember(model, r.sender) &&
            membership !== undefined &&
            membership.amountSats > 0n &&
            !isInPreparePhase(model) &&
            model.deployedSigners.has(r.signer) &&
            r.signer !== membership.signer
          );
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const membership = model.bondMemberships.get(r.sender)!;
          pickedBond = membership.bondIndex;
          const base = (membership.amountSats * r.withdrawalBips) / 10000n;
          const withdrawal = base > 0n ? base : 1n;
          const balanceBefore = sbtcBalance(r.sender);
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.sender),
          );
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );

          // Act

          const receipt = txErr(
            real.contracts.pox5.unstakeSbtc({
              signerManager: r.signer,
              amountToWithdrawalSats: withdrawal,
            }),
            r.sender,
          );

          // Assert

          expect(totalStakedBefore).toBe(model.totalSbtcStaked);
          expect(receipt.value).toBe(errorCodes.ERR_INVALID_OLD_SIGNER_MANAGER);
          // Membership, custody, and the staked total all untouched.
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            membershipBefore,
          );
          expect(sbtcBalance(r.sender)).toBe(balanceBefore);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalStakedBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'unstake-sbtc-err-invalid-old-signer',
            value: `bond ${pickedBond}`,
            error: 'ERR_INVALID_OLD_SIGNER_MANAGER',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `unstake-sbtc-err-invalid-old-signer(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'})`,
      };
    });
