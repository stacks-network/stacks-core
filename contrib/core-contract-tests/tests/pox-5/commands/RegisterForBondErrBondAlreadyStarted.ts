import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondAllowanceKey,
  bondStartCycle,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  logCommand,
  minUstxForSats,
  refreshModel,
  rewardCycleToBurnHeight,
  trackCommandRun,
} from './utils';
import { err } from '@clarigen/core';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Set-up bonds the staker is allowlisted for whose lock has already started.
 * Excludes any bond the staker is a member of, so the no-mutation read is
 * null.
 */
function startedAllowlistedBonds(
  model: Readonly<Model>,
  staker: string,
): bigint[] {
  if (model.bondMemberships.has(staker)) return [];
  const result: bigint[] = [];
  for (const [bondIndex] of model.bonds) {
    if (!model.bondAllowances.has(bondAllowanceKey(bondIndex, staker))) {
      continue;
    }
    const startHeight = rewardCycleToBurnHeight(
      model,
      bondStartCycle(model, bondIndex),
    );
    if (model.burnBlockHeight >= startHeight) result.push(bondIndex);
  }
  return result;
}

/**
 * Register for a set-up, allowlisted bond whose lock has already started. The
 * sender clears the amount floor, so the `< burn-block-height bond-start-height`
 * assertion is the gate that trips: the call reverts with
 * ERR_BOND_ALREADY_STARTED before the already-staked / too-much-sats checks
 * and mutates nothing.
 */
export const RegisterForBondErrBondAlreadyStarted = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      bondPick: fc.nat(),
      signerIndex: fc.nat(),
      sats: fc.bigInt({ min: 1n, max: 1_000_000n }),
      extraUstx: fc.bigInt({ min: 0n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      let pickedSigner: string | undefined;
      return {
        // A set-up, allowlisted, already-started bond (sender not a member),
        // outside the prepare phase, leaves the started check as the gate. A
        // granted signer keeps the handle well formed.
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          grantedSigners(model).length > 0 &&
          startedAllowlistedBonds(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_bond_already_started');

          // Arrange
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = startedAllowlistedBonds(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const config = model.bonds.get(bondIndex)!;
          // Clear the amount floor; that check sits before the started one, so
          // it must not fire first.
          const amountUstx =
            minUstxForSats(r.sats, config.stxValueRatio, config.minUstxRatio) +
            r.extraUstx;
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
              amountUstx,
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
          expect(receipt.value).toBe(errorCodes.ERR_BOND_ALREADY_STARTED);
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
            action: 'register-for-bond-err-bond-already-started',
            value: `bond ${bondIndex}`,
            error: 'ERR_BOND_ALREADY_STARTED',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-bond-already-started(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'}${
            pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''
          })`,
      };
    });
