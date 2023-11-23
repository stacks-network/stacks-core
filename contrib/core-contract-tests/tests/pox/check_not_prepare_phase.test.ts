import { Cl } from "@stacks/transactions";
import { beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

const accounts = simnet.getAccounts();
const alice = accounts.get("wallet_1")!;
const bob = accounts.get("wallet_2")!;
const charlie = accounts.get("wallet_3")!;

function expectBurnBlockHeight(height: number) {
  const { result: bbh } = simnet.callReadOnlyFn(
    "pox-helper",
    "get-bbh",
    [],
    alice
  );
  expect(bbh).toBeUint(height);
}

describe("test pox prepare phase check", () => {
  it("should return false during prepare phase", () => {
    simnet.mineEmptyBlocks(998);
    expectBurnBlockHeight(999);
    let { result } = simnet.callReadOnlyFn(
      "pox-4",
      "check-not-prepare-phase",
      [],
      alice
    );
    expect(result).toBeBool(true);

    simnet.mineEmptyBlock();
    expectBurnBlockHeight(1000);
    ({ result } = simnet.callReadOnlyFn(
      "pox-4",
      "check-not-prepare-phase",
      [],
      alice
    ));
    expect(result).toBeBool(false);

    simnet.mineEmptyBlocks(50);
    expectBurnBlockHeight(1050);
    ({ result } = simnet.callReadOnlyFn(
      "pox-4",
      "check-not-prepare-phase",
      [],
      alice
    ));
    expect(result).toBeBool(false);

    simnet.mineEmptyBlock();
    expectBurnBlockHeight(1051);
    ({ result } = simnet.callReadOnlyFn(
      "pox-4",
      "check-not-prepare-phase",
      [],
      alice
    ));
    expect(result).toBeBool(true);
  });
});
