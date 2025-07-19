import fc from "fast-check";
import type { Model, Real } from "./types";
import { expect } from "vitest";
import { txOk } from "@clarigen/test";
import { getWalletNameByAddress, logCommand, trackCommandRun } from "./utils";

export const UpdateRecipient = (accounts: Real["accounts"]) =>
  fc.record({
    sender: fc.constantFrom(
      ...Object.values(accounts).map((x) => x.address),
    ),
    newRecipient: fc.constantFrom(
      ...Object.values(accounts as Record<string, { address: string }>).map((
        acc,
      ) => acc.address),
    ),
  }).map((r) => ({
    check: (model: Readonly<Model>) => {
      return model.initialized === true && model.recipient === r.sender;
    },
    run: (model: Model, real: Real) => {
      trackCommandRun(model, "update-recipient");

      const receipt = txOk(
        real.contracts.sip031.updateRecipient(r.newRecipient),
        r.sender,
      );
      expect(receipt.value).toBe(true);

      model.recipient = r.newRecipient;

      logCommand({
        sender: getWalletNameByAddress(r.sender),
        status: "ok",
        action: "update-recipient",
        value: `to ${getWalletNameByAddress(r.newRecipient)}`,
      });
    },
    toString: () => `update-recipient to ${r.newRecipient}`,
  }));
