import fc from "fast-check";
import { accounts, project } from "../clarigen-types";
import { projectFactory } from "@clarigen/core";
import { rov } from "@clarigen/test";
import { test } from "vitest";

import { Claim } from "./commands/Claim";
import { ClaimErr } from "./commands/ClaimErr";
import { MineBlocks } from "./commands/MineBlocks";
import { Mint } from "./commands/Mint";
import { MintInitial } from "./commands/MintInitial";
import { Model, Real } from "./commands/types";
import { UpdateRecipient } from "./commands/UpdateRecipient";
import { UpdateRecipientErr } from "./commands/UpdateRecipientErr";
import { reportCommandRuns } from "./commands/utils";

const contracts = projectFactory(project, "simnet");

test("SIP-031 Stateful", () => {
  const real: Real = {
    accounts,
    contracts,
  };

  const model: Model = {
    balance: 0n,
    blockHeight: rov(contracts.sip031.getDeployBlockHeight()),
    constants: contracts.sip031.constants,
    deployBlockHeight: rov(contracts.sip031.getDeployBlockHeight()),
    initialized: false,
    recipient: accounts.deployer.address,
    statistics: new Map(),
    totalClaimed: 0n,
  };

  const invariants = [
    Claim(accounts),
    ClaimErr(accounts),
    MineBlocks(),
    Mint(),
    MintInitial(accounts),
    UpdateRecipient(accounts),
    UpdateRecipientErr(accounts),
  ];

  fc.assert(
    fc.property(
      fc.commands(invariants, { size: "+1" }),
      (cmds) => {
        const state = () => ({ model: model, real: real });
        fc.modelRun(state, cmds);
      },
    ),
    { numRuns: 100, verbose: 2 },
  );

  reportCommandRuns(model);
});
