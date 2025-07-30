import fc from "fast-check";
import type { Model, Real } from "./types";
import { expect } from "vitest";
import { txErr } from "@clarigen/test";
import { getWalletNameByAddress, logCommand, trackCommandRun } from "./utils";

export const UpdateRecipientErr = (accounts: Real["accounts"]) =>
  fc.record({
    sender: fc.constantFrom(
      ...Object.values(accounts).map((x) => x.address),
    ),
    newRecipient: fc.constantFrom(
      ...Object.values(accounts).map((x) => x.address),
    ),
  }).map((r) => ({
    check: (model: Readonly<Model>) => {
      return model.initialized === true && model.recipient !== r.sender;
    },
    run: (model: Model, real: Real) => {
      trackCommandRun(model, "update-recipient-err");

      const receipt = txErr(
        real.contracts.sip031.updateRecipient(r.newRecipient),
        r.sender,
      );
      expect(receipt.value).toBe(model.constants.ERR_NOT_ALLOWED);

      logCommand({
        sender: getWalletNameByAddress(r.sender),
        status: "err",
        action: "update-recipient-err",
        error: "ERR_NOT_ALLOWED",
      });
    },
    toString: () => `update-recipient-err as ${r.sender}`,
  }));
