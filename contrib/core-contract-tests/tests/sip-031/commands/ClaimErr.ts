import fc from "fast-check";
import type { Model, Real } from "./types";
import {
  calculateClaimable,
  getWalletNameByAddress,
  logCommand,
  trackCommandRun,
} from "./utils";
import { expect } from "vitest";
import { txErr } from "@clarigen/test";

export const ClaimErr = (accounts: Real["accounts"]) =>
  fc.record({
    sender: fc.constantFrom(
      ...Object.values(accounts).map((x) => x.address),
    ),
  }).map((r) => ({
    check: (model: Readonly<Model>) => {
      if (model.initialized !== true) {
        return false;
      }

      if (model.recipient !== r.sender) {
        return true;
      }

      const claimable = calculateClaimable(model);
      return claimable === 0n;
    },
    run: (model: Model, real: Real) => {
      trackCommandRun(model, "claim-err");

      const expectedError = model.recipient !== r.sender
        ? model.constants.ERR_NOT_ALLOWED
        : model.constants.ERR_NOTHING_TO_CLAIM;
      const receipt = txErr(real.contracts.sip031.claim(), r.sender);
      expect(receipt.value).toBe(expectedError);

      const errString = expectedError === model.constants.ERR_NOT_ALLOWED
        ? "ERR_NOT_ALLOWED"
        : "ERR_NOTHING_TO_CLAIM";
      logCommand({
        sender: getWalletNameByAddress(r.sender),
        status: "err",
        action: "claim-err",
        error: errString,
      });
    },
    toString: () => `claim-err as ${r.sender}`,
  }));
