import fc from "fast-check";
import type { Model, Real } from "./types";
import { txOk } from "@clarigen/test";
import { logCommand, trackCommandRun } from "./utils";

export const MintInitial = (accounts: Real["accounts"]) =>
  fc.record({}).map(() => ({
    check: (model: Readonly<Model>) => model.initialized === false,
    run: (model: Model, real: Real) => {
      trackCommandRun(model, "mint-initial");

      const contracts = real.contracts;
      const indirect = contracts.sip031Indirect;
      const sip031 = contracts.sip031;

      // Split initial mint into two transfers to wallet_4 from wallet_5 and wallet_6.
      txOk(
        indirect.transferStx(
          sip031.constants.INITIAL_MINT_AMOUNT / 2n,
          accounts.wallet_4.address,
        ),
        accounts.wallet_5.address,
      );
      txOk(
        indirect.transferStx(
          sip031.constants.INITIAL_MINT_AMOUNT / 2n,
          accounts.wallet_4.address,
        ),
        accounts.wallet_6.address,
      );

      // Forward full amount from wallet_4 into the SIP-031 contract.
      txOk(
        indirect.transferStx(
          sip031.constants.INITIAL_MINT_AMOUNT,
          sip031.identifier,
        ),
        accounts.wallet_4.address,
      );

      model.initialized = true;
      model.balance = sip031.constants.INITIAL_MINT_AMOUNT;

      logCommand({
        sender: undefined,
        status: "ok",
        action: "setup-initial-funding",
        value: `amount ${sip031.constants.INITIAL_MINT_AMOUNT}`,
      });
    },
    toString: () => `setup-initial-funding`,
  }));
