import fc from 'fast-check';
import type { BondMembership, Model, Real } from './types';
import {
  assertBondSignerSharesForCycle,
  assertBondStakerSharesForCycle,
  assertBondTotalSharesForCycle,
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  bondAllowanceKey,
  bondStartCycle,
  candidateSignerIds,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  logCommand,
  minUstxForSats,
  modelAddStakerToBondCycles,
  modelAddStakerToCycles,
  refreshModel,
  registrableBondsForStaker,
  trackCommandRun,
} from './utils';
import {
  BOND_LENGTH_CYCLES,
  proxyRegisterForBondOk,
  sbtcBalance,
} from '../pox-5-helpers';
import { rov } from '@clarigen/test';
import { expect } from 'vitest';

/** Fresh sBTC bond registration through a forwarding proxy contract. */
export const RegisterForBondViaContractCaller = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
      bondPick: fc.nat(),
      satsBips: fc.bigInt({ min: 1n, max: 10000n }),
      extraUstx: fc.bigInt({ min: 1n, max: 1_000_000_000_000n }),
    })
    .map((r) => {
      let pickedBond: bigint | undefined;
      return {
        check: (model: Readonly<Model>) =>
          !isInPreparePhase(model) &&
          grantedSigners(model).includes(r.signer) &&
          (model.sbtcBalances.get(r.sender) ?? 0n) > 0n &&
          !model.stakers.has(r.sender) &&
          registrableBondsForStaker(model, r.sender).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-for-bond_proxy');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const bonds = registrableBondsForStaker(model, r.sender);
          const bondIndex = bonds[r.bondPick % bonds.length];
          pickedBond = bondIndex;
          const config = model.bonds.get(bondIndex)!;
          const allowance = model.bondAllowances.get(
            bondAllowanceKey(bondIndex, r.sender),
          )!;
          const balance = model.sbtcBalances.get(r.sender)!;
          const maxSats = allowance < balance ? allowance : balance;
          const satsBase = (maxSats * r.satsBips) / 10000n;
          const sats = satsBase > 0n ? satsBase : 1n;
          const amountUstx =
            minUstxForSats(sats, config.stxValueRatio, config.minUstxRatio) +
            r.extraUstx;
          const firstRewardCycle = bondStartCycle(model, bondIndex);
          const lastCycle = firstRewardCycle + BOND_LENGTH_CYCLES - 1n;
          const membership: BondMembership = {
            bondIndex,
            amountUstx,
            signer: r.signer,
            isL1Lock: false,
            amountSats: sats,
          };

          // Act

          const receipt = proxyRegisterForBondOk({
            sender: r.sender,
            bondIndex,
            signerManager: r.signer,
            amountUstx,
            sats,
          });

          // Update model

          model.sbtcBalances.set(r.sender, balance - sats);
          model.totalSbtcStaked += sats;
          model.contractSbtcBalance += sats;
          model.bondTotalStaked.set(
            bondIndex,
            (model.bondTotalStaked.get(bondIndex) ?? 0n) + sats,
          );
          model.bondMemberships.set(r.sender, membership);
          modelAddStakerToCycles(
            model,
            r.sender,
            r.signer,
            firstRewardCycle,
            BOND_LENGTH_CYCLES,
            amountUstx,
            false,
          );
          modelAddStakerToBondCycles(
            model,
            r.sender,
            r.signer,
            bondIndex,
            firstRewardCycle,
            BOND_LENGTH_CYCLES,
            sats,
          );

          // Assert

          expect(receipt.value.bondIndex).toBe(bondIndex);
          expect(receipt.value.satsTotal).toBe(sats);
          expect(receipt.value.amountUstx).toBe(amountUstx);
          expect(receipt.value.firstRewardCycle).toBe(firstRewardCycle);
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            membership,
          );
          expect(sbtcBalance(r.sender)).toBe(balance - sats);
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            model.totalSbtcStaked,
          );
          expect(
            rov(real.contracts.pox5.getTotalSbtcStakedForBond(bondIndex)),
          ).toBe(model.bondTotalStaked.get(bondIndex)!);
          assertSignerDelegationForCycle(
            model,
            real,
            firstRewardCycle,
            r.signer,
          );
          assertSignerCycleMembership(model, real, firstRewardCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, firstRewardCycle);
          assertStakerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            r.sender,
            r.signer,
          );
          assertBondTotalSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
          );
          assertBondSignerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            r.signer,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            r.signer,
            r.sender,
          );
          assertSignerDelegationForCycle(model, real, lastCycle, r.signer);
          assertSignerCycleMembership(model, real, lastCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, lastCycle);
          assertStakerSharesForCycle(
            model,
            real,
            lastCycle,
            r.sender,
            r.signer,
          );
          assertBondTotalSharesForCycle(model, real, lastCycle, bondIndex);
          assertBondSignerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            r.signer,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            r.signer,
            r.sender,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'register-for-bond-proxy',
            value: `bond ${bondIndex} sats ${sats}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-for-bond-proxy(${getWalletNameByAddress(
            r.sender,
          )}, bond ${pickedBond ?? '?'}, ${r.signer.split('.').pop()})`,
      };
    });
