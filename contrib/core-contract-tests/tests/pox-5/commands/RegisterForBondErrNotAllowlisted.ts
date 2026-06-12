import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondAllowanceKey,
  getWalletNameByAddress,
  grantedSigners,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { err } from '@clarigen/core';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/** Set-up bonds the staker is NOT allowlisted for (no allowance row). */
function unallowlistedBonds(model: Readonly<Model>, staker: string): bigint[] {
  const result: bigint[] = [];
  for (const [bondIndex] of model.bonds) {
    if (!model.bondAllowances.has(bondAllowanceKey(bondIndex, staker))) {
      result.push(bondIndex);
    }
  }
  return result;
}

/**
 * Register for a set-up bond the sender is not allowlisted for.
 * `protocol-bond-allowances` is unwrapped right after the bond lookup, so the
 * call reverts with ERR_NOT_ALLOWLISTED before the prepare-phase guard and
 * mutates nothing.
 */
export const RegisterForBondErrNotAllowlisted = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      bondPick: fc.nat(),
      signerIndex: fc.nat(),
      sats: fc.bigInt({ min: 1n, max: 1_000_000n }),
      amountUstx: fc.bigInt({ min: 0n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      let pickedSigner: string | undefined;
      return {
        // A set-up bond with no allowance for the sender is the only reason
        // ERR_NOT_ALLOWLISTED fires; the sender holds no membership so the
        // no-mutation read is null. A granted signer keeps the handle well
        // formed. The prepare-phase guard sits after this gate, so phase is
        // free.
        check: (model: Readonly<Model>) =>
          unallowlistedBonds(model, r.sender).length > 0 &&
          !model.bondMemberships.has(r.sender) &&
          grantedSigners(model).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_not_allowlisted');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = unallowlistedBonds(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const balanceBefore = sbtcBalance(r.sender);
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.sender),
          );
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );

          // Act

          const receipt = txErr(
            real.contracts.pox5.registerForBond({
              bondIndex,
              signerManager: signer,
              amountUstx: r.amountUstx,
              btcLockup: err(r.sats),
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          // Pre-state matched the model: no membership, the model's staked
          // total.
          expect(membershipBefore).toBeNull();
          expect(totalStakedBefore).toBe(model.totalSbtcStaked);
          expect(receipt.value).toBe(errorCodes.ERR_NOT_ALLOWLISTED);
          // Rejected call left membership, sBTC custody, and the staked total
          // untouched.
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            membershipBefore,
          );
          expect(sbtcBalance(r.sender)).toBe(balanceBefore);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalStakedBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'register-for-bond-err-not-allowlisted',
            value: `bond ${bondIndex}`,
            error: 'ERR_NOT_ALLOWLISTED',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-not-allowlisted(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'}${
            pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''
          })`,
      };
    });
