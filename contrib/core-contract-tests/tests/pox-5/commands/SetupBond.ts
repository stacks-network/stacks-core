import fc from 'fast-check';
import type { BondConfig, Model, Real } from './types';
import {
  bondAllowanceKey,
  eligibleBondIndex,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { deployer } from '../pox-5-helpers';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * Admin sets up the bond whose creation window is currently open. `setup-bond`
 * is admin-only and time-windowed, so the target bond is derived from the burn
 * height. Allowlists a random subset of wallets at independent max-sats so
 * register-for-bond can later hit both the allowed and ERR_NOT_ALLOWLISTED
 * paths. Asserts the stored config and per-staker allowances read back.
 */
export const SetupBond = (accounts: Real['accounts']) => {
  const addresses = Object.values(accounts).map((a) => a.address);
  return fc
    .record({
      // Round-tripped verbatim; the band just keeps counterexamples legible.
      targetRate: fc.bigInt({ min: 1n, max: 10000n }),
      stxValueRatio: fc.bigInt({ min: 1n, max: 10000n }),
      minUstxRatio: fc.bigInt({ min: 1n, max: 10000n }),
      // Stored as-is; capped under the buff(683) type max to stay in domain.
      earlyUnlockBytes: fc.uint8Array({ maxLength: 100 }),
      // Index-aligned with the wallets: a max-sats allowlists that wallet; null
      // leaves it off, so each run mixes allowlisted and excluded principals.
      allowances: fc.array(
        fc.option(fc.bigInt({ min: 0n, max: 1_000_000_000n }), { nil: null }),
        { minLength: addresses.length, maxLength: addresses.length },
      ),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        // Need an open setup window, on a bond not already set up.
        check: (model: Readonly<Model>) => {
          const idx = eligibleBondIndex(model);
          return idx !== undefined && !model.bonds.has(idx);
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'setup-bond');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bondIndex = eligibleBondIndex(model)!;
          pickedBond = bondIndex;
          const allowlist = addresses.flatMap((staker, i) =>
            r.allowances[i] === null
              ? []
              : [{ staker, maxSats: r.allowances[i]! }],
          );
          const config: BondConfig = {
            targetRate: r.targetRate,
            stxValueRatio: r.stxValueRatio,
            minUstxRatio: r.minUstxRatio,
            earlyUnlockBytes: r.earlyUnlockBytes,
          };

          // Act

          const receipt = txOk(
            real.contracts.pox5.setupBond({
              bondIndex,
              targetRate: r.targetRate,
              stxValueRatio: r.stxValueRatio,
              minUstxRatio: r.minUstxRatio,
              earlyUnlockBytes: r.earlyUnlockBytes,
              allowlist,
            }),
            deployer,
          );

          // Update model

          model.bonds.set(bondIndex, config);
          for (let i = 0; i < addresses.length; i++) {
            if (r.allowances[i] !== null) {
              model.bondAllowances.set(
                bondAllowanceKey(bondIndex, addresses[i]),
                r.allowances[i]!,
              );
            }
          }

          // Assert

          // Receipt echoes the index and the total allocated sats.
          expect(receipt.value.bondIndex).toBe(bondIndex);
          expect(receipt.value.maxAllocationSats).toBe(
            allowlist.reduce((sum, e) => sum + e.maxSats, 0n),
          );
          // Stored config reads back.
          expect(rov(real.contracts.pox5.getProtocolBond(bondIndex))).toEqual(
            config,
          );
          // Per-staker allowances read back; whole-map compare, not per-line.
          const contractAllowances = Object.fromEntries(
            addresses.map((s) => [
              s,
              rov(real.contracts.pox5.getBondAllowance(bondIndex, s)),
            ]),
          );
          const modelAllowances = Object.fromEntries(
            addresses.map((s) => [
              s,
              model.bondAllowances.get(bondAllowanceKey(bondIndex, s)) ?? null,
            ]),
          );
          expect(contractAllowances).toEqual(modelAllowances);

          logCommand({
            action: 'setup-bond',
            value: `bond: ${bondIndex} allowlisted: ${allowlist.length}/${addresses.length}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () => `setup-bond(${pickedBond ?? '?'})`,
      };
    });
};
