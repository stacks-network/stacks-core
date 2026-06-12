import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  logCommand,
  minUstxForSats,
  refreshModel,
  registrableBondsForStaker,
  trackCommandRun,
} from './utils';
import { err } from '@clarigen/core';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Register for a bond with one uSTX below the `min-ustx-for-sats-amount`
 * floor. The amount check is the first `asserts!` after the prepare-phase
 * guard, so a registrable bond outside the prepare phase reverts with
 * ERR_INSUFFICIENT_STX before the started / already-staked / too-much-sats
 * checks and mutates nothing.
 */
export const RegisterForBondErrInsufficientStx = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      bondPick: fc.nat(),
      signerIndex: fc.nat(),
      // Extra sats above the floor that forces a non-zero minimum, so the
      // shortfall `amountUstx = minUstx - 1` is a real uint and the chosen
      // sats varies run to run.
      extraSats: fc.bigInt({ min: 0n, max: 1_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      let pickedSigner: string | undefined;
      return {
        // A registrable bond outside the prepare phase leaves the amount floor
        // as the gate we trip. A granted signer keeps the handle well formed.
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          grantedSigners(model).length > 0 &&
          registrableBondsForStaker(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_insufficient_stx');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = registrableBondsForStaker(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const config = model.bonds.get(bondIndex)!;
          // Smallest sats making the floor at least 1: solve
          // (((svr*sats)/100)*mur)/10000 >= 1 for sats, then add extra. Even
          // when both ratios are 1 this keeps the floor positive.
          const ratioProduct = config.stxValueRatio * config.minUstxRatio;
          const minSatsForFloor =
            (1_000_000n + ratioProduct - 1n) / ratioProduct;
          const sats = minSatsForFloor + r.extraSats;
          const minUstx = minUstxForSats(
            sats,
            config.stxValueRatio,
            config.minUstxRatio,
          );
          // One uSTX under the floor: the exact value that trips the check.
          const amountUstx = minUstx - 1n;
          const balanceBefore = sbtcBalance(r.sender);
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.sender),
          );
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );

          // The shortfall is a real uint only if the floor is positive.
          expect(minUstx).toBeGreaterThanOrEqual(1n);

          // Act

          const receipt = txErr(
            real.contracts.pox5.registerForBond({
              bondIndex,
              signerManager: signer,
              amountUstx,
              btcLockup: err(sats),
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          // Pre-state matched the model: no membership, the model's staked
          // total.
          expect(membershipBefore).toBeNull();
          expect(totalStakedBefore).toBe(model.totalSbtcStaked);
          expect(receipt.value).toBe(errorCodes.ERR_INSUFFICIENT_STX);
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
            action: 'register-for-bond-err-insufficient-stx',
            value: `bond ${bondIndex} ustx ${amountUstx}`,
            error: 'ERR_INSUFFICIENT_STX',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-insufficient-stx(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'}${
            pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''
          })`,
      };
    });
