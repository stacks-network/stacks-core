import fc from "fast-check";
import type { Model, Real } from "./types";
import { txOk } from "@clarigen/test";
import { logCommand, trackCommandRun } from "./utils";

export const Mint = () =>
  fc.record({
    amount: fc.bigInt(1n, 100000000n),
  }).map((r) => ({
    check: (model: Readonly<Model>) => model.initialized === true,
    run: (model: Model, real: Real) => {
      trackCommandRun(model, "mint");

      txOk(
        real.contracts.sip031Indirect.transferStx(
          r.amount,
          real.contracts.sip031.identifier,
        ),
        real.accounts.wallet_4.address,
      );

      model.balance += r.amount;

      logCommand({
        sender: undefined,
        status: "ok",
        action: "mint",
        value: `amount ${r.amount}`,
      });
    },
    toString: () => `mint ${r.amount}`,
  }));
