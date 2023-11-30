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
  it("should return true during prepare phase (1000 - 1049)", () => {
    let { result } = simnet.callReadOnlyFn(
      "pox-4",
      "check-prepare-phase",
      [Cl.uint(999)],
      alice
    );
    expect(result).toBeBool(false);

    ({ result } = simnet.callReadOnlyFn(
      "pox-4",
      "check-prepare-phase",
      [Cl.uint(1000)],
      alice
    ));
    expect(result).toBeBool(true);

    ({ result } = simnet.callReadOnlyFn(
      "pox-4",
      "check-prepare-phase",
      [Cl.uint(1049)],
      alice
    ));
    expect(result).toBeBool(true);

    ({ result } = simnet.callReadOnlyFn(
      "pox-4",
      "check-prepare-phase",
      [Cl.uint(1050)],
      alice
    ));
    expect(result).toBeBool(false);
  });
});
