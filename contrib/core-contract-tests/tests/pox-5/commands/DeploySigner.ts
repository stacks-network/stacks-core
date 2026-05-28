import fc from 'fast-check';
import type { Model, Real } from './types';
import { logCommand, refreshModel, trackCommandRun } from './utils';
import { deployTestSignerContract } from '../pox-5-helpers';
import { rov } from '@clarigen/test';
import { expect } from 'vitest';

export const DeploySigner = () =>
  fc.constant(null).map(() => {
    let name: string | undefined;
    return {
      // Allow max 10 signer manager contracts to be deployed.
      check: (model: Readonly<Model>) => model.deployedSigners.size < 10,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'deploy-signer');

        // Arrange
        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const expectedName = `test-pox-5-signer-${model.deployedSigners.size}`;
        const expectedId = `${real.accounts.deployer.address}.${expectedName}`;
        const sourceBefore = real.network.getContractSource(expectedId);

        // Act
        name = expectedName;
        const contract = deployTestSignerContract(name);

        // Assert

        // Model says this identifier has never been deployed; simnet agrees.
        expect(sourceBefore).toBeUndefined();
        // Clarigen handle was constructed for the principal we expected.
        expect(contract.identifier).toBe(expectedId);
        // simnet now hosts the contract source at the new identifier.
        expect(
          real.network.getContractSource(contract.identifier),
        ).not.toBeNull();
        // Freshly deployed signer-manager has not been registered with pox-5.
        expect(
          rov(real.contracts.pox5.getSignerInfo(contract.identifier)),
        ).toBeNull();

        // Update model
        model.deployedSigners.add(contract.identifier);

        logCommand({
          action: 'deploy-signer',
          value: contract.identifier,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () => `deploy-signer`,
    };
  });
