import fc from 'fast-check';
import type { Model, Real } from './types';
import {
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

/**
 * Register for a bond-index that was never set up. `protocol-bonds` is the
 * first thing `register-for-bond` unwraps, so the call reverts with
 * ERR_BOND_NOT_FOUND before any other gate and mutates nothing.
 */
export const RegisterForBondErrBondNotFound = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Wide index space; `check` keeps only the ones with no `protocol-bonds`
      // row. Bonds are sparse, so almost every draw is unused.
      bondIndex: fc.bigInt({ min: 0n, max: 1_000_000n }),
      signerIndex: fc.nat(),
      sats: fc.bigInt({ min: 1n, max: 1_000_000n }),
      amountUstx: fc.bigInt({ min: 0n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // The bond must not exist (the only reason ERR_BOND_NOT_FOUND fires)
        // and the sender must hold no membership (so the no-mutation read is
        // null). A granted signer keeps the signer-manager handle well formed.
        check: (model: Readonly<Model>) =>
          !model.bonds.has(r.bondIndex) &&
          !model.bondMemberships.has(r.sender) &&
          grantedSigners(model).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_bond_not_found');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
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
              bondIndex: r.bondIndex,
              signerManager: signer,
              amountUstx: r.amountUstx,
              btcLockup: err(r.sats),
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert

          // Pre-state matched the model: no membership, the model's staked total.
          expect(membershipBefore).toBeNull();
          expect(totalStakedBefore).toBe(model.totalSbtcStaked);
          expect(receipt.value).toBe(errorCodes.ERR_BOND_NOT_FOUND);
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
            action: 'register-for-bond-err-bond-not-found',
            value: `bond ${r.bondIndex}`,
            error: 'ERR_BOND_NOT_FOUND',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-bond-not-found(${getWalletNameByAddress(
            r.sender,
          )}, bond ${r.bondIndex}${
            pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''
          })`,
      };
    });
