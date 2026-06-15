import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  grantedSigners,
  isContractCallerAllowed,
  isInPreparePhase,
  logCommand,
  refreshModel,
  stxAccount,
  trackCommandRun,
} from './utils';
import { errorCodes, proxyStake } from '../pox-5-helpers';
import { rov } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * A proxy stake with no live allowance reaches pox-5's `check-caller-allowed`
 * and rejects with ERR_UNAUTHORIZED_CALLER. Earlier stake guards are kept valid
 * so this branch is the one that fires.
 */
export const StakeViaContractCallerErrUnauthorized = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      amountUstx: fc.bigInt({ min: 1000000n, max: 1000000000000n }),
      numCycles: fc.bigInt({ min: 1n, max: 96n }),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        !isContractCallerAllowed(model, r.sender) &&
        grantedSigners(model).includes(r.signer) &&
        !isInPreparePhase(model),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'stake_proxy_err_unauthorized_caller');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const firstLockedCycle = currentRewardCycle(model) + 1n;
        const lastLockedCycle = firstLockedCycle + r.numCycles - 1n;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const accountBefore = stxAccount(real, r.sender);
        const firstDelegatedBefore = rov(
          real.contracts.pox5.getAmountDelegatedForSigner(
            r.signer,
            firstLockedCycle,
          ),
        );
        const firstMembershipBefore = rov(
          real.contracts.pox5.getSignerCycleMembership(
            r.sender,
            firstLockedCycle,
          ),
        );
        const firstSharesBefore = rov(
          real.contracts.pox5.getStakerSharesStakedForCycle(
            r.sender,
            firstLockedCycle,
            null,
            r.signer,
          ),
        );
        const firstTotalBefore = rov(
          real.contracts.pox5.getUstxDelegatedForCycle(firstLockedCycle),
        );
        const lastDelegatedBefore = rov(
          real.contracts.pox5.getAmountDelegatedForSigner(
            r.signer,
            lastLockedCycle,
          ),
        );
        const lastMembershipBefore = rov(
          real.contracts.pox5.getSignerCycleMembership(
            r.sender,
            lastLockedCycle,
          ),
        );
        const lastSharesBefore = rov(
          real.contracts.pox5.getStakerSharesStakedForCycle(
            r.sender,
            lastLockedCycle,
            null,
            r.signer,
          ),
        );
        const lastTotalBefore = rov(
          real.contracts.pox5.getUstxDelegatedForCycle(lastLockedCycle),
        );

        // Act

        const result = proxyStake({
          sender: r.sender,
          signerManager: r.signer,
          amountUstx: r.amountUstx,
          numCycles: r.numCycles,
          startBurnHeight: real.network.burnBlockHeight,
        });

        // Assert

        expect(result.value.isOk).toBe(false);
        expect(result.value.value).toBe(errorCodes.ERR_UNAUTHORIZED_CALLER);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual(
          stakerInfoBefore,
        );
        expect(stxAccount(real, r.sender)).toEqual(accountBefore);
        expect(
          rov(
            real.contracts.pox5.getAmountDelegatedForSigner(
              r.signer,
              firstLockedCycle,
            ),
          ),
        ).toBe(firstDelegatedBefore);
        expect(
          rov(
            real.contracts.pox5.getSignerCycleMembership(
              r.sender,
              firstLockedCycle,
            ),
          ),
        ).toEqual(firstMembershipBefore);
        expect(
          rov(
            real.contracts.pox5.getStakerSharesStakedForCycle(
              r.sender,
              firstLockedCycle,
              null,
              r.signer,
            ),
          ),
        ).toBe(firstSharesBefore);
        expect(
          rov(real.contracts.pox5.getUstxDelegatedForCycle(firstLockedCycle)),
        ).toBe(firstTotalBefore);
        expect(
          rov(
            real.contracts.pox5.getAmountDelegatedForSigner(
              r.signer,
              lastLockedCycle,
            ),
          ),
        ).toBe(lastDelegatedBefore);
        expect(
          rov(
            real.contracts.pox5.getSignerCycleMembership(
              r.sender,
              lastLockedCycle,
            ),
          ),
        ).toEqual(lastMembershipBefore);
        expect(
          rov(
            real.contracts.pox5.getStakerSharesStakedForCycle(
              r.sender,
              lastLockedCycle,
              null,
              r.signer,
            ),
          ),
        ).toBe(lastSharesBefore);
        expect(
          rov(real.contracts.pox5.getUstxDelegatedForCycle(lastLockedCycle)),
        ).toBe(lastTotalBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-proxy-err-unauthorized-caller',
          error: 'ERR_UNAUTHORIZED_CALLER',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-proxy-err-unauthorized-caller(${getWalletNameByAddress(
          r.sender,
        )}, ${r.signer.split('.').pop()})`,
    }));
