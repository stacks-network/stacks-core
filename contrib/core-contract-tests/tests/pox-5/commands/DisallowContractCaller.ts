import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  contractCallerAllowanceKey,
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { AUTH_PROXY_ID } from '../pox-5-helpers';
import { txOk } from '@clarigen/test';
import { expect } from 'vitest';

/** A wallet deletes its existing proxy authorization. */
export const DisallowContractCaller = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        model.contractCallerAllowances.has(
          contractCallerAllowanceKey(r.sender, AUTH_PROXY_ID),
        ),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'disallow-contract-caller');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;

        // Act

        const receipt = txOk(
          real.contracts.pox5.disallowContractCaller(AUTH_PROXY_ID),
          r.sender,
        );

        // Update model

        model.contractCallerAllowances.delete(
          contractCallerAllowanceKey(r.sender, AUTH_PROXY_ID),
        );

        // Assert

        expect(receipt.value).toBe(true);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'disallow-contract-caller',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `disallow-contract-caller(${getWalletNameByAddress(r.sender)})`,
    }));
