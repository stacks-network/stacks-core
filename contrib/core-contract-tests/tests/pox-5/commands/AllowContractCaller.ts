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

// The contract accepts any uint expiration. Keep the generated offset high
// enough that allowances can survive long random command stretches, while
// still allowing broader sweeps to mine past the expiration and hit
// unauthorized proxy calls through the same model entry.
const MAX_CONTRACT_CALLER_EXPIRATION_OFFSET = 1000n;

/**
 * A wallet authorizes the proxy contract to call pox-5 on its behalf. The
 * optional expiration is generated as a future offset so later proxy commands
 * can exercise both live allowances and expiration after MineBitcoinBlocks.
 */
export const AllowContractCaller = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      expirationOffset: fc.option(
        fc.bigInt({ min: 1n, max: MAX_CONTRACT_CALLER_EXPIRATION_OFFSET }),
        { nil: null },
      ),
    })
    .map((r) => {
      let pickedExpiration: bigint | null | undefined;
      return {
        check: (_model: Readonly<Model>) => true,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'allow-contract-caller');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const expiration =
            r.expirationOffset === null
              ? null
              : model.burnBlockHeight + r.expirationOffset;
          pickedExpiration = expiration;

          // Act

          const receipt = txOk(
            real.contracts.pox5.allowContractCaller(AUTH_PROXY_ID, expiration),
            r.sender,
          );

          // Update model

          model.contractCallerAllowances.set(
            contractCallerAllowanceKey(r.sender, AUTH_PROXY_ID),
            expiration,
          );

          // Assert

          expect(receipt.value).toBe(true);

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'allow-contract-caller',
            value:
              expiration === null
                ? 'no-expiration'
                : `until-burn-ht ${expiration}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `allow-contract-caller(${getWalletNameByAddress(r.sender)}, ${
            pickedExpiration === null ? 'none' : (pickedExpiration ?? '?')
          })`,
      };
    });
