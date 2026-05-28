import fc from 'fast-check';
import type { Model, Real } from './types';
import { logCommand, refreshModel, trackCommandRun } from './utils';
import { deployTestSignerContract } from '../pox-5-helpers';

export const DeploySigner = () =>
  fc.constant(null).map(() => {
    let name: string | undefined;
    return {
      // Allow max 10 signer manager contract to be deployed.
      check: (model: Readonly<Model>) => model.deployedSigners.size < 10,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'deploy-signer');

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;

        name = `test-pox-5-signer-${model.deployedSigners.size}`;
        const contract = deployTestSignerContract(name);
        model.deployedSigners.add(contract.identifier);

        logCommand({
          action: 'deploy-signer',
          value: contract.identifier,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () => `deploy-signer(${name ?? 'pending'})`,
    };
  });
