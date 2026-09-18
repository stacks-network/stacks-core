import fc from 'fast-check';
import type { Model, Real } from './types';
import { getWalletNameByAddress, logCommand, refreshModel } from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance, testSigner } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * unstake-sbtc from a sender with no bond membership. The membership unwrap is
 * the first thing the call does, so it reverts with ERR_NOT_BOND_PARTICIPANT
 * and mutates nothing.
 */
export const UnstakeSbtcErrNotBondParticipant = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Irrelevant on the rejected branch; the membership unwrap fires first.
      amountSats: fc.bigInt({ min: 1n, max: 1_000_000n }),
    })
    .map((r) => {
      return {
        // The sender must hold no membership, the only reason u34 fires.
        check: (model: Readonly<Model>) => !model.bondMemberships.has(r.sender),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const balanceBefore = sbtcBalance(r.sender);
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );

          // Act

          const receipt = txErr(
            real.contracts.pox5.unstakeSbtc({
              signerManager: testSigner.identifier,
              amountToWithdrawalSats: r.amountSats,
            }),
            r.sender,
          );

          // Assert

          expect(totalStakedBefore).toBe(model.totalSbtcStaked);
          expect(receipt.value).toBe(errorCodes.ERR_NOT_BOND_PARTICIPANT);
          // No membership existed and none was created; custody untouched.
          expect(
            rov(real.contracts.pox5.getBondMembership(r.sender)),
          ).toBeNull();
          expect(sbtcBalance(r.sender)).toBe(balanceBefore);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalStakedBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'unstake-sbtc-err-not-bond-participant',
            error: 'ERR_NOT_BOND_PARTICIPANT',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `unstake-sbtc-err-not-bond-participant(${getWalletNameByAddress(
            r.sender,
          )})`,
      };
    });
