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
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * unstake-sbtc during the prepare phase. With a valid amount and the correct
 * signer, the prepare-phase guard is the only reason it reverts, so the call
 * fails with ERR_STAKE_IN_PREPARE_PHASE and mutates nothing.
 */
export const UnstakeSbtcErrInPreparePhase = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      withdrawalBips: fc.bigInt({ min: 1n, max: 10000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        // An active member with sats to withdraw, in the prepare phase. The
        // amount stays within the custody so the amount check passes first.
        check: (model: Readonly<Model>) => {
          const membership = model.bondMemberships.get(r.sender);
          return (
            isActiveBondMember(model, r.sender) &&
            membership !== undefined &&
            membership.amountSats > 0n &&
            isInPreparePhase(model)
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
              signerManager: membership.signer,
              amountToWithdrawalSats: withdrawal,
            }),
            r.sender,
          );

          // Assert

          expect(totalStakedBefore).toBe(model.totalSbtcStaked);
          expect(receipt.value).toBe(errorCodes.ERR_STAKE_IN_PREPARE_PHASE);
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
            action: 'unstake-sbtc-err-in-prepare-phase',
            value: `bond ${pickedBond}`,
            error: 'ERR_STAKE_IN_PREPARE_PHASE',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `unstake-sbtc-err-in-prepare-phase(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'})`,
      };
    });
