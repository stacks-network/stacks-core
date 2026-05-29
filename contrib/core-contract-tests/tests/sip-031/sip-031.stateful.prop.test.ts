import fc from 'fast-check';
import { accounts, project } from '../clarigen-types';
import { projectFactory } from '@clarigen/core';
import { rov } from '@clarigen/test';
import { test } from 'vitest';

import { Claim } from './commands/Claim';
import { ClaimErr } from './commands/ClaimErr';
import { MineBlocks } from './commands/MineBlocks';
import { Mint } from './commands/Mint';
import { MintInitial } from './commands/MintInitial';
import { Model, Real } from './commands/types';
import { UpdateRecipient } from './commands/UpdateRecipient';
import { UpdateRecipientErr } from './commands/UpdateRecipientErr';
import { reportCommandRuns } from './commands/utils';

const contracts = projectFactory(project, 'simnet');

test('SIP-031 Stateful', async () => {
  const real: Real = {
    accounts,
    contracts,
  };

  // Shared across iterations so the final report reflects every run.
  const statistics = new Map<string, number>();

  const invariants = [
    Claim(accounts),
    ClaimErr(accounts),
    MineBlocks(),
    Mint(),
    MintInitial(accounts),
    UpdateRecipient(accounts),
    UpdateRecipientErr(accounts),
  ];

  await fc.assert(
    fc.asyncProperty(fc.commands(invariants, { size: '+1' }), async (cmds) => {
      // Reset simnet so each property iteration (and each shrinking
      // attempt) runs against a fresh chain. Without this, model and
      // simnet can accumulate divergent state across runs.
      await simnet.initSession(process.cwd(), './Clarinet.toml', null);

      const model: Model = {
        balance: 0n,
        blockHeight: rov(contracts.sip031.getDeployBlockHeight()),
        constants: contracts.sip031.constants,
        deployBlockHeight: rov(contracts.sip031.getDeployBlockHeight()),
        initialized: false,
        recipient: accounts.deployer.address,
        statistics,
        totalClaimed: 0n,
      };

      fc.modelRun(() => ({ model, real }), cmds);
    }),
    { numRuns: 100, verbose: 2 },
  );

  reportCommandRuns(statistics);
});
