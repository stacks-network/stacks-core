import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { ok } from '@clarigen/core';
import { rov, txErr } from '@clarigen/test';
import { buildL1Lockup, errorCodes, testSigner } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * register-for-bond on the L1 path with a constructed lockup. The lockup's
 * script, amount, and single-tx merkle root all line up, but its block header
 * cannot match simnet's burn-block hash (no real preimage exists), so
 * verify-block-header fails first with ERR_INVALID_BTC_HEADER. This is the
 * only L1-registration branch reachable in simnet; the success path and the
 * script/amount/merkle errors need real headers and live in the integration
 * tests.
 */
export const RegisterForBondErrInvalidBtcHeader = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      staker: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      bondPick: fc.nat(),
      sats: fc.bigInt({ min: 1n, max: 1_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        // Any set-up bond exists, so `verify-l1-lockups` gets past its
        // bond-not-found check and reaches the header verification.
        check: (model: Readonly<Model>) => model.bonds.size > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_err_invalid_btc_header');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = [...model.bonds.keys()];
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const lockup = buildL1Lockup({
            staker: r.staker,
            sats: r.sats,
            bondIndex,
          });
          const membershipBefore = rov(
            real.contracts.pox5.getBondMembership(r.staker),
          );
          const totalStakedBefore = rov(
            real.contracts.pox5.getTotalSbtcStaked(),
          );

          // Act

          const receipt = txErr(
            real.contracts.pox5.registerForBond({
              bondIndex,
              signerManager: testSigner.identifier,
              amountUstx: 1_000_000_000n,
              btcLockup: ok({
                outputs: [lockup],
                stakerUnlockBytes: new Uint8Array(),
              }),
              signerCalldata: null,
            }),
            r.staker,
          );

          // Assert

          expect(receipt.value).toBe(errorCodes.ERR_INVALID_BTC_HEADER);
          // No membership formed and no sBTC custodied.
          expect(rov(real.contracts.pox5.getBondMembership(r.staker))).toEqual(
            membershipBefore,
          );
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalStakedBefore,
          );

          logCommand({
            sender: getWalletNameByAddress(r.staker),
            action: 'register-for-bond-err-invalid-btc-header',
            value: `bond ${bondIndex}`,
            error: 'ERR_INVALID_BTC_HEADER',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-err-invalid-btc-header(${getWalletNameByAddress(
            r.staker,
          )}, bond ${pickedBond ?? '?'})`,
      };
    });
