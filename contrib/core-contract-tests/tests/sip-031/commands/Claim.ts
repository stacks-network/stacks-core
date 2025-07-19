import fc from "fast-check";
import type { Model, Real } from "./types";
import {
  calculateClaimable,
  getWalletNameByAddress,
  logCommand,
  trackCommandRun,
} from "./utils";
import { expect } from "vitest";
import { txOk } from "@clarigen/test";

export const Claim = (accounts: Real["accounts"]) =>
  fc.record({
    sender: fc.constantFrom(
      ...Object.values(accounts).map((x) => x.address),
    ),
  }).map((r) => ({
    check: (model: Readonly<Model>) => {
      const claimable = calculateClaimable(model);
      return model.initialized === true && model.recipient === r.sender &&
        claimable > 0n;
    },
    run: (model: Model, real: Real) => {
      trackCommandRun(model, "claim");

      const expectedClaim = calculateClaimable(model);
      const receipt = txOk(real.contracts.sip031.claim(), r.sender);
      expect(receipt.value).toBe(expectedClaim);

      model.balance -= expectedClaim;
      model.totalClaimed += expectedClaim;

      logCommand({
        sender: getWalletNameByAddress(r.sender),
        status: "ok",
        action: "claim",
        value: `amount ${expectedClaim}`,
      });
    },
    toString: () => `claim`,
  }));
