import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  bondEndCycle,
  bondRolloverUnlockHeight,
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  grantedSigners,
  isActiveBondMember,
  isInPreparePhase,
  logCommand,
  refreshModel,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * A bond member attempts to roll into STX-only staking before the existing
 * bond's L1 collateral unlock window. The bond no longer overlaps the new
 * stake, but verify-bond-rollover-window rejects with ERR_ROLLOVER_TOO_EARLY.
 */
export const StakeErrRolloverTooEarly = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      numCycles: fc.bigInt({ min: 1n, max: 96n }),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) => {
        const membership = model.bondMemberships.get(r.sender);
        return (
          membership !== undefined &&
          isActiveBondMember(model, r.sender) &&
          currentRewardCycle(model) + 1n >=
            bondEndCycle(model, membership.bondIndex) &&
          model.burnBlockHeight <
            bondRolloverUnlockHeight(model, membership.bondIndex) &&
          !model.stakers.has(r.sender) &&
          !isInPreparePhase(model) &&
          grantedSigners(model).includes(r.signer)
        );
      },
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const membership = model.bondMemberships.get(r.sender)!;
        const membershipBefore = rov(
          real.contracts.pox5.getBondMembership(r.sender),
        );
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const balanceBefore = sbtcBalance(r.sender);
        const totalStakedBefore = rov(real.contracts.pox5.getTotalSbtcStaked());

        // Act

        const receipt = txErr(
          real.contracts.pox5.stake({
            signerManager: r.signer,
            amountUstx: membership.amountUstx,
            numCycles: r.numCycles,
            startBurnHt: real.network.burnBlockHeight,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Assert

        expect(membershipBefore).toEqual(membership);
        expect(stakerInfoBefore).toBeNull();
        expect(receipt.value).toBe(errorCodes.ERR_ROLLOVER_TOO_EARLY);
        expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toEqual(
          membershipBefore,
        );
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );
        expect(sbtcBalance(r.sender)).toBe(balanceBefore);
        expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
          totalStakedBefore,
        );

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-err-rollover-too-early',
          value: `bond ${membership.bondIndex}`,
          error: 'ERR_ROLLOVER_TOO_EARLY',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-err-rollover-too-early(${getWalletNameByAddress(
          r.sender,
        )}, ${r.signer.split('.').pop()})`,
    }));
