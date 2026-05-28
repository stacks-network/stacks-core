import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  trackCommandRun,
} from './utils';
import { registerSigner, testSignerHandle } from '../pox-5-helpers';

export const RegisterSigner = (accounts: Real['accounts']) =>
  fc
    .record({
      caller: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signerIndex: fc.nat(),
      seed: fc.uint8Array({ minLength: 48, maxLength: 48 }),
      authId: fc.bigInt({ min: 1n, max: 1_000_000_000n }),
    })
    .map((r) => {
      let pickedSignerId: string | undefined;
      // Pick a deployed-but-not-yet-registered signer from the model.
      const pickSignerId = (model: Readonly<Model>) => {
        const unregistered = [...model.deployedSigners].filter(
          (id) => !model.signers.has(id),
        );
        if (unregistered.length === 0) return undefined;
        return unregistered[r.signerIndex % unregistered.length];
      };

      return {
        check: (model: Readonly<Model>) => pickSignerId(model) !== undefined,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'register-signer');

          const signerId = pickSignerId(model)!;
          pickedSignerId = signerId;
          const signerManager = testSignerHandle(signerId);

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;

          registerSigner({
            signerManager,
            caller: r.caller,
            seed: r.seed,
            authId: r.authId,
          });
          model.signers.add(signerId);

          logCommand({
            sender: getWalletNameByAddress(r.caller),
            action: 'register-signer',
            value: signerId,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `register-signer(${getWalletNameByAddress(r.caller)}${pickedSignerId ? `, ${pickedSignerId.split('.').pop()}` : ''})`,
      };
    });
