import fc from 'fast-check';
import { accounts, project } from '../clarigen-types';
import { projectFactory } from '@clarigen/core';
import { test } from 'vitest';

import { MineBitcoinBlocks } from './commands/MineBlocks';
import { Stake } from './commands/Stake';
import { StakeErrAlreadyStaked } from './commands/StakeErrAlreadyStaked';
import { Model, Real } from './commands/types';
import { reportCommandRuns } from './commands/utils';
import { initSimnet } from '@stacks/clarinet-sdk';
import { REWARD_CYCLE_LENGTH, initPox5 } from './pox-5-helpers';

const contracts = projectFactory(project, 'simnet');

test('pox-5 stateful property test', async () => {
  const real: Real = {
    accounts,
    contracts,
    network: await initSimnet(),
  };

  // initPox5 calls setBurnchainParameters with configured firstBurnHeight,
  // prepareCycleLength, rewardCycleLength, beginPox5RewardCycle, and sets the
  // deployer as bond admin.
  initPox5();

  const model: Model = {
    stakers: new Map(),
    signers: new Set(),
    burnBlockHeight: BigInt(real.network.burnBlockHeight),
    rewardCycleLength: REWARD_CYCLE_LENGTH,
    firstBurnHeight: 0n,
    prepareCycleLength: 10n,
    statistics: new Map(),
  };

  const invariants = [
    Stake(accounts),
    StakeErrAlreadyStaked(accounts),
    MineBitcoinBlocks(),
  ];

  fc.assert(
    fc.property(fc.commands(invariants, { size: 'medium' }), (cmds) => {
      const state = () => ({ model: model, real: real });
      fc.modelRun(state, cmds);
    }),
    { numRuns: 100, verbose: 2 },
  );

  reportCommandRuns(model);
}, 30_000 /* ms timeout */);
