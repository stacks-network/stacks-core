import fc from 'fast-check';
import { accounts, project } from '../clarigen-types';
import { projectFactory } from '@clarigen/core';
import { test } from 'vitest';

import { AssertModelInvariants } from './commands/AssertModelInvariants';
import { AssertSignerInvariants } from './commands/AssertSignerInvariants';
import { AssertStakerInvariants } from './commands/AssertStakerInvariants';
import { DeploySigner } from './commands/DeploySigner';
import { MineBitcoinBlocks } from './commands/MineBlocks';
import { RegisterSigner } from './commands/RegisterSigner';
import { RegisterSignerErrGrantUsed } from './commands/RegisterSignerErrGrantUsed';
import { RevokeSignerGrant } from './commands/RevokeSignerGrant';
import { RevokeSignerGrantErrUnauthorized } from './commands/RevokeSignerGrantErrUnauthorized';
import { RevokeSignerGrantNonexistent } from './commands/RevokeSignerGrantNonexistent';
import { RotateSignerKey } from './commands/RotateSignerKey';
import { SetupBond } from './commands/SetupBond';
import { SetupBondErrAlreadySetup } from './commands/SetupBondErrAlreadySetup';
import { SetupBondErrTooLate } from './commands/SetupBondErrTooLate';
import { SetupBondErrTooSoon } from './commands/SetupBondErrTooSoon';
import { SetupBondErrUnauthorized } from './commands/SetupBondErrUnauthorized';
import { Stake } from './commands/Stake';
import { StakeErrAlreadyStaked } from './commands/StakeErrAlreadyStaked';
import { StakeErrGrantRevoked } from './commands/StakeErrGrantRevoked';
import { StakeErrInPreparePhase } from './commands/StakeErrInPreparePhase';
import { StakeErrInvalidNumCycles } from './commands/StakeErrInvalidNumCycles';
import { StakeErrSignerNotFound } from './commands/StakeErrSignerNotFound';
import { StakeExtend } from './commands/StakeExtend';
import { StakeUpdate } from './commands/StakeUpdate';
import { Unstake } from './commands/Unstake';
import { UnstakeErrInPreparePhase } from './commands/UnstakeErrInPreparePhase';
import { Model, Real } from './commands/types';
import { reportCommandRuns } from './commands/utils';
import { initSimnet } from '@stacks/clarinet-sdk';
import {
  REWARD_CYCLE_LENGTH,
  initBootPox5,
  pox5,
  testSigner,
} from './pox-5-helpers';

const contracts = {
  ...projectFactory(project, 'simnet'),
  // Use the lock-aware boot pox-5: clarinet-sdk only applies STX locking to
  // ST0…AMW42H.pox-5, which signer-manager.clar / test-pox-5-signer.clar now
  // target. The local [contracts.pox-5] is not lock-aware in simnet.
  pox5,
};

// Local sweeps override via env, e.g.:
//   FAST_CHECK_NUM_RUNS=1000 FAST_CHECK_SIZE=large FAST_CHECK_TIMEOUT_MS=600000 npx vitest run ...
const NUM_RUNS = Number(process.env.FAST_CHECK_NUM_RUNS ?? 100);
const TEST_TIMEOUT_MS = Number(process.env.FAST_CHECK_TIMEOUT_MS ?? 120_000);
// Command-sequence length scale. CI default `medium`; sweeps crank to `large`.
const SIZE = (process.env.FAST_CHECK_SIZE ?? 'medium') as fc.Size;
// Shrinking can collapse any failure onto a non-idempotent command (one whose
// `check` lets it re-run against already-consumed state), masking the real
// divergence; noShrink shows what actually failed first.
const NO_SHRINK = process.env.FAST_CHECK_NO_SHRINK === '1';

test(
  'pox-5 stateful property test',
  async () => {
    const real: Real = {
      accounts,
      contracts,
      network: await initSimnet(),
    };

    // Configure the boot pox-5's burnchain params (the instance the commands
    // stake against).
    initBootPox5();

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
      bonds: new Map(),
      bondAllowances: new Map(),
      firstBondPeriodCycle: 1n,
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
      StakeExtend(accounts),
      Unstake(accounts),
      StakeErrAlreadyStaked(accounts),
      StakeErrSignerNotFound(accounts),
      StakeErrInvalidNumCycles(accounts),
      StakeErrInPreparePhase(accounts),
      StakeErrGrantRevoked(accounts),
      UnstakeErrInPreparePhase(accounts),
      SetupBond(accounts),
      SetupBondErrUnauthorized(accounts),
      SetupBondErrAlreadySetup(accounts),
      SetupBondErrTooLate(accounts),
      SetupBondErrTooSoon(accounts),
      MineBitcoinBlocks(),
      AssertSignerInvariants(),
      AssertStakerInvariants(accounts),
      AssertModelInvariants(accounts),
    ];

    fc.assert(
      fc.property(fc.commands(invariants, { size: SIZE }), (cmds) => {
        const state = () => ({ model: model, real: real });
        fc.modelRun(state, cmds);
      }),
      { numRuns: NUM_RUNS, verbose: 2, endOnFailure: NO_SHRINK },
    );

    reportCommandRuns(model);
  },
  TEST_TIMEOUT_MS,
);
