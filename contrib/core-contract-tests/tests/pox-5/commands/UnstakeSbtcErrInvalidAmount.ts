import fc from 'fast-check';
import type { Model, Real } from './types';
import { getWalletNameByAddress, logCommand, refreshModel } from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * unstake-sbtc for more sats than the member custodies. The amount check sits
 * in the `let`, before the prepare-phase and signer gates, so it reverts with
 * ERR_INVALID_UNSTAKE_SBTC_AMOUNT and mutates nothing.
 */
export const UnstakeSbtcErrInvalidAmount = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // How far over the custodied amount to ask for; >= 1 so it always
      // exceeds.
      excessSats: fc.bigInt({ min: 1n, max: 1_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        // Any bond member: withdrawing more than they hold trips u37, which
        // fires before the prepare-phase and signer checks.
        check: (model: Readonly<Model>) => model.bondMemberships.has(r.sender),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const membership = model.bondMemberships.get(r.sender)!;
          pickedBond = membership.bondIndex;
          const withdrawal = membership.amountSats + r.excessSats;
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
          expect(receipt.value).toBe(
            errorCodes.ERR_INVALID_UNSTAKE_SBTC_AMOUNT,
          );
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
            action: 'unstake-sbtc-err-invalid-amount',
            value: `bond ${pickedBond} sats ${withdrawal}`,
            error: 'ERR_INVALID_UNSTAKE_SBTC_AMOUNT',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `unstake-sbtc-err-invalid-amount(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'})`,
      };
    });
