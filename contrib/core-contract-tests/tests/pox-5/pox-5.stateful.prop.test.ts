import fc from 'fast-check';
import { accounts, project } from '../clarigen-types';
import { projectFactory } from '@clarigen/core';
import { test } from 'vitest';

import { AssertModelInvariants } from './commands/AssertModelInvariants';
import { DeploySigner } from './commands/DeploySigner';
import { MineBitcoinBlocks } from './commands/MineBlocks';
import { RegisterSigner } from './commands/RegisterSigner';
import { RegisterSignerErrGrantUsed } from './commands/RegisterSignerErrGrantUsed';
import { RevokeSignerGrant } from './commands/RevokeSignerGrant';
import { RevokeSignerGrantErrUnauthorized } from './commands/RevokeSignerGrantErrUnauthorized';
import { RevokeSignerGrantNonexistent } from './commands/RevokeSignerGrantNonexistent';
import { RotateSignerKey } from './commands/RotateSignerKey';
import { Stake } from './commands/Stake';
import { StakeErrAlreadyStaked } from './commands/StakeErrAlreadyStaked';
import { StakeErrInvalidNumCycles } from './commands/StakeErrInvalidNumCycles';
import { StakeErrSignerNotFound } from './commands/StakeErrSignerNotFound';
import { StakeUpdate } from './commands/StakeUpdate';
import { Unstake } from './commands/Unstake';
import { UnstakeErrInPreparePhase } from './commands/UnstakeErrInPreparePhase';
import { Model, Real } from './commands/types';
import { reportCommandRuns } from './commands/utils';
import { initSimnet } from '@stacks/clarinet-sdk';
import { REWARD_CYCLE_LENGTH, initPox5, testSigner } from './pox-5-helpers';

const contracts = projectFactory(project, 'simnet');

// Local sweeps override via env, e.g.:
//   FAST_CHECK_NUM_RUNS=1000 FAST_CHECK_SIZE=large FAST_CHECK_TIMEOUT_MS=600000 npx vitest run ...
const NUM_RUNS = Number(process.env.FAST_CHECK_NUM_RUNS ?? 100);
const TEST_TIMEOUT_MS = Number(process.env.FAST_CHECK_TIMEOUT_MS ?? 120_000);
// Command-sequence length scale. CI default `medium`; sweeps crank to `large`.
const SIZE = (process.env.FAST_CHECK_SIZE ?? 'medium') as fc.Size;

test(
  'pox-5 stateful property test',
  async () => {
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
      ustxDelegatedPerCycle: new Map(),
      signerDelegatedPerCycle: new Map(),
      stakerSignerCycleMemberships: new Map(),
      stakerSharesStakedForCycle: new Map(),
      // The default test-pox-5-signer is already deployed via Clarinet.toml;
      // DeploySigner adds further instances during the run.
      deployedSigners: new Set([testSigner.identifier]),
      signers: new Map(),
      usedGrants: new Set(),
      activeGrants: new Set(),
      burnBlockHeight: BigInt(real.network.burnBlockHeight),
      rewardCycleLength: REWARD_CYCLE_LENGTH,
      firstBurnHeight: 0n,
      prepareCycleLength: 10n,
      statistics: new Map(),
    };

    const invariants = [
      DeploySigner(),
      RegisterSigner(accounts),
      RegisterSignerErrGrantUsed(accounts),
      RotateSignerKey(),
      RevokeSignerGrant(),
      RevokeSignerGrantNonexistent(),
      RevokeSignerGrantErrUnauthorized(accounts),
      Stake(accounts),
      StakeUpdate(accounts),
      Unstake(accounts),
      StakeErrAlreadyStaked(accounts),
      StakeErrSignerNotFound(accounts),
      StakeErrInvalidNumCycles(accounts),
      UnstakeErrInPreparePhase(accounts),
      MineBitcoinBlocks(),
      AssertModelInvariants(accounts),
    ];

    fc.assert(
      fc.property(fc.commands(invariants, { size: SIZE }), (cmds) => {
        const state = () => ({ model: model, real: real });
        fc.modelRun(state, cmds);
      }),
      { numRuns: NUM_RUNS, verbose: 2 },
    );

    reportCommandRuns(model);
  },
  TEST_TIMEOUT_MS,
);
