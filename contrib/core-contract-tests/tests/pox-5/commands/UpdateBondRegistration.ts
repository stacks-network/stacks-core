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
  bondEndCycle,
  bondStartCycle,
  currentRewardCycle,
  getWalletNameByAddress,
  grantedSigners,
  isActiveBondMember,
  isInPreparePhase,
  logCommand,
  modelAddStakerToBondCycles,
  modelAddStakerToCycles,
  modelRemoveStakerFromBondCycles,
  modelRemoveStakerFromCycles,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txOk } from '@clarigen/test';
import { sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * Move an active bond participant's signer to a different granted signer for
 * the bond's remaining cycles. No sBTC moves. Asserts the receipt, the updated
 * `get-bond-membership` (only the signer changes), unchanged sBTC custody, and
 * at the first and last touched cycle the per-cycle signer delegation for BOTH
 * the new and old signer, the staker's cycle membership, the cycle total, the
 * staker shares under both signers (the vacated old cell must read 0), and the
 * bond per-cycle shares (total once, plus signer and staker shares under both
 * signers; the old signer's bond cells vacate to 0).
 */
export const UpdateBondRegistration = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signerIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // An active bond member, outside the prepare phase, with at least one
        // other granted signer to switch to (current signer excluded).
        check: (model: Readonly<Model>) =>
          isActiveBondMember(model, r.sender) &&
          !isInPreparePhase(model) &&
          grantedSigners(model).some(
            (s) => s !== model.bondMemberships.get(r.sender)!.signer,
          ),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'update-bond-registration');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const membership = model.bondMemberships.get(r.sender)!;
          const oldSigner = membership.signer;
          const candidates = grantedSigners(model).filter(
            (s) => s !== oldSigner,
          );
          const newSigner = candidates[r.signerIndex % candidates.length];
          pickedSigner = newSigner;
          const bondIndex = membership.bondIndex;
          const currentCycle = currentRewardCycle(model);
          const bondStart = bondStartCycle(model, bondIndex);
          const bondEnd = bondEndCycle(model, bondIndex);
          // clamp(current + 1, bondStart, bondEnd): the next cycle, floored at
          // the bond start (if not yet begun) and capped at its end.
          const nextCycle = currentCycle + 1n;
          const firstRewardCycle =
            nextCycle > bondEnd
              ? bondEnd
              : nextCycle < bondStart
                ? bondStart
                : nextCycle;
          const numCycles = bondEnd - firstRewardCycle;
          const lastCycle = firstRewardCycle + numCycles - 1n;
          const newMembership: BondMembership = {
            ...membership,
            signer: newSigner,
          };
          const totalSbtcBefore = rov(real.contracts.pox5.getTotalSbtcStaked());
          const balanceBefore = sbtcBalance(r.sender);

          // Act

          const receipt = txOk(
            real.contracts.pox5.updateBondRegistration({
              signerManager: newSigner,
              oldSignerManager: oldSigner,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Update model
          // Replay the contract's remove-then-re-add over the touched cycles.
          // remove reads the stored membership, so it subtracts from the OLD
          // signer; re-add joins the NEW signer (bond => isStxStaking false).
          // Before the asserts so they compare against the committed mirror.
          modelRemoveStakerFromCycles(
            model,
            r.sender,
            firstRewardCycle,
            numCycles,
          );
          modelAddStakerToCycles(
            model,
            r.sender,
            newSigner,
            firstRewardCycle,
            numCycles,
            membership.amountUstx,
            false,
          );
          // Bond shares move the same way: remove from the OLD signer (zeroing
          // the staker cell there), then re-add the unchanged sats to the NEW
          // signer. amountSats is preserved across the move.
          modelRemoveStakerFromBondCycles(
            model,
            r.sender,
            oldSigner,
            bondIndex,
            firstRewardCycle,
            numCycles,
            membership.amountSats,
          );
          modelAddStakerToBondCycles(
            model,
            r.sender,
            newSigner,
            bondIndex,
            firstRewardCycle,
            numCycles,
            membership.amountSats,
          );
          model.bondMemberships.set(r.sender, newMembership);

          // Assert

          // Receipt echoes the move: new signer, old signer, preserved fields.
          expect(receipt.value.staker).toBe(r.sender);
          expect(receipt.value.signer).toBe(newSigner);
          expect(receipt.value.oldSigner).toBe(oldSigner);
          expect(receipt.value.bondIndex).toBe(bondIndex);
          expect(receipt.value.amountUstx).toBe(membership.amountUstx);
          expect(receipt.value.amountSats).toBe(membership.amountSats);
          expect(receipt.value.firstRewardCycle).toBe(firstRewardCycle);
          expect(receipt.value.numCycles).toBe(numCycles);
          expect(receipt.value.isL1Lock).toBe(membership.isL1Lock);
          // Membership now points at the new signer; everything else preserved.
          expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
            newMembership,
          );
          // sBTC custody is unchanged: the total and the staker's balance
          // hold.
          expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
            totalSbtcBefore,
          );
          expect(sbtcBalance(r.sender)).toBe(balanceBefore);

          // Per-cycle reads at the first touched cycle. The new signer gains
          // the delegation, the old signer's cell drops to its mirrored value,
          // and the staker's vacated old-signer shares cell reads 0.
          assertSignerDelegationForCycle(
            model,
            real,
            firstRewardCycle,
            newSigner,
          );
          assertSignerDelegationForCycle(
            model,
            real,
            firstRewardCycle,
            oldSigner,
          );
          assertSignerCycleMembership(model, real, firstRewardCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, firstRewardCycle);
          assertStakerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            r.sender,
            newSigner,
          );
          assertStakerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            r.sender,
            oldSigner,
          );
          // Bond shares at the first cycle: the cycle total (once), and the
          // signer- and staker-shares under BOTH signers. The new signer gains
          // the sats; the old signer's cells must read 0 (vacated).
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
            newSigner,
          );
          assertBondSignerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            oldSigner,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            newSigner,
            r.sender,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            firstRewardCycle,
            bondIndex,
            oldSigner,
            r.sender,
          );

          // Per-cycle reads at the last touched cycle.
          assertSignerDelegationForCycle(model, real, lastCycle, newSigner);
          assertSignerDelegationForCycle(model, real, lastCycle, oldSigner);
          assertSignerCycleMembership(model, real, lastCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, lastCycle);
          assertStakerSharesForCycle(
            model,
            real,
            lastCycle,
            r.sender,
            newSigner,
          );
          assertStakerSharesForCycle(
            model,
            real,
            lastCycle,
            r.sender,
            oldSigner,
          );
          // Bond shares at the last cycle, both signers.
          assertBondTotalSharesForCycle(model, real, lastCycle, bondIndex);
          assertBondSignerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            newSigner,
          );
          assertBondSignerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            oldSigner,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            newSigner,
            r.sender,
          );
          assertBondStakerSharesForCycle(
            model,
            real,
            lastCycle,
            bondIndex,
            oldSigner,
            r.sender,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'update-bond-registration',
            value: `bond ${bondIndex} -> ${newSigner.split('.').pop()}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `update-bond-registration(${getWalletNameByAddress(r.sender)}${
            pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''
          })`,
      };
    });
