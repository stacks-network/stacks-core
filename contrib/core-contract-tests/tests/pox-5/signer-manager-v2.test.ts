// Behaviour tests for `contracts/signer-manager-v2.clar`, covering the changes
// it makes relative to v1. Driven through raw simnet calls (rather than the
// clarigen handles the v1 suite uses) so the generated types file does not have
// to be regenerated to run these.
import { Cl, ClarityValue } from "@stacks/transactions";
import { beforeEach, describe, expect, it } from "vitest";
import { hex } from "@scure/base";
import {
  currentCycle,
  expectOk,
  fundRewards,
  managerPrincipal,
  num,
  registerSigner,
  SBTC,
  POX5,
} from "./helpers/rewards-fixture";

const MANAGER = "signer-manager-v2";

const ERR_NO_CLAIMABLE_REWARDS = 1001;
const ERR_UNAUTHORIZED_ADMIN = 1002;
const ERR_INVALID_FEES_BIPS = 1005;
const ERR_INSUFFICIENT_FEES = 1007;
const ERR_NO_REFUNDS = 1010;
const ERR_BELOW_DUST_LIMIT = 1012;
const ERR_BELOW_MIN_CLAIM = 1013;
const ERR_INVALID_MIN_CLAIM = 1014;
const ERR_LAST_ADMIN = 1015;
const ERR_NOT_SELF = 1016;
const ERR_NO_REFUND_CREDIT = 1019;

const DUST_LIMIT = 546;

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!; // admin by `(map-set admins tx-sender true)`
const staker = accounts.get("wallet_1")!;
const other = accounts.get("wallet_2")!;
const dave = accounts.get("wallet_3")!;

// The principal allowed to accept/reject sBTC withdrawals.
const SBTC_SIGNER = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4";

const manager = () => managerPrincipal(deployer, MANAGER);

// Read the cycle length off pox-5 rather than hardcoding it: these tests run
// against the boot pox-5 (1050 burn blocks per cycle), not the shortened one
// `initPox5()` configures for the clarigen-based suite.
const cycleStart = (cycle: number) =>
  num(
    simnet.callReadOnlyFn(
      POX5,
      "reward-cycle-to-burn-height",
      [Cl.uint(cycle)],
      deployer,
    ).result,
  );
// Read lazily, not at module load: module bodies execute before the per-file
// simnet reset, so a length captured there can belong to whatever pox-5 state
// the previously-loaded test file left behind.
const cycleLength = () => cycleStart(1) - cycleStart(0);

/** Advance the burn chain by `n` whole reward cycles. */
const mineCycles = (n: number) => simnet.mineEmptyBurnBlocks(cycleLength() * n);

const POX_ADDR = Cl.tuple({
  version: Cl.buffer(new Uint8Array([0x01])),
  hashbytes: Cl.buffer(new Uint8Array(20).fill(0xab)),
});

/** Unwrap a tuple ClarityValue into its field -> ClarityValue map. */
const tupleFields = (cv: any): Record<string, ClarityValue> => cv.value;

const ro = (fn: string, args: any[] = [], sender = deployer) =>
  simnet.callReadOnlyFn(MANAGER, fn, args, sender).result;

const tx = (fn: string, args: any[], sender: string) =>
  simnet.callPublicFn(MANAGER, fn, args, sender).result;

const sbtcBalance = (who: string) =>
  num(
    (
      simnet.callReadOnlyFn(
        `${SBTC}.sbtc-token`,
        "get-balance",
        [Cl.principal(who)],
        deployer,
      ).result as any
    ).value,
  );

const setPayoutConfig = (maxFee: number, minClaim: number, sender = staker) =>
  tx("set-payout-config", [POX_ADDR, Cl.uint(maxFee), Cl.uint(minClaim)], sender);

/**
 * Drive pox-5 to real rewards for `staker` under the v2 manager and have the
 * manager pull the pot. `rewardPot` is the sBTC transferred into pox-5, which
 * is what `get-rewards` sees. Returns the cycle and the gross (pre-fee) reward.
 */
function earnRewards(rewardPot: number) {
  expectOk(registerSigner(deployer, MANAGER, POX5).result, "register-self");

  const cycle = currentCycle(deployer, POX5);
  const startBurnHt = num(
    simnet.callReadOnlyFn(
      POX5,
      "reward-cycle-to-burn-height",
      [Cl.uint(cycle)],
      deployer,
    ).result,
  );
  expectOk(
    simnet.callPublicFn(
      POX5,
      "stake",
      [
        Cl.principal(manager()),
        Cl.uint(100_000_000_000),
        Cl.uint(2),
        Cl.uint(startBurnHt),
        Cl.none(),
      ],
      staker,
    ).result,
    "stake",
  );

  const rewardCycle = cycle + 1;
  const target = num(
    simnet.callReadOnlyFn(
      POX5,
      "reward-cycle-to-burn-height",
      [Cl.uint(rewardCycle + 1)],
      deployer,
    ).result,
  );
  simnet.mineEmptyBurnBlocks(Math.max(1, target - simnet.burnBlockHeight + 2));

  expectOk(fundRewards(staker, rewardPot, POX5).result, "fund rewards");
  expectOk(
    simnet.callPublicFn(POX5, "calculate-rewards", [Cl.list([])], deployer)
      .result,
    "calculate-rewards",
  );
  expectOk(
    simnet.callPublicFn(
      MANAGER,
      "claim-rewards",
      [Cl.list([]), Cl.uint(rewardCycle)],
      deployer,
    ).result,
    "claim-rewards",
  );

  const gross = num(
    simnet.callReadOnlyFn(
      POX5,
      "get-earned-staker-rewards",
      [
        Cl.principal(manager()),
        Cl.uint(rewardCycle),
        Cl.none(),
        Cl.principal(staker),
      ],
      deployer,
    ).result,
  );
  return { cycle: rewardCycle, gross };
}

const claim = (cycle: number, sender: string) =>
  tx(
    "claim-staker-rewards",
    [Cl.principal(staker), Cl.uint(cycle), Cl.none()],
    sender,
  );

// The bitcoin header hash at `height`, required by the sBTC accept fork check.
function burnHeader(height: number): Uint8Array {
  const result = simnet.execute(`(get-burn-block-info? header-hash u${height})`);
  return hex.decode((result.result as any).value.value);
}

describe("fee increases are delayed by 2 cycles, decreases are immediate", () => {
  it("queues an increase and only activates it after the delay", () => {
    expect(ro("get-active-fee-bips")).toBeUint(0);
    const start = currentCycle(deployer, POX5);

    expect(tx("update-fees", [Cl.uint(300)], deployer)).toBeOk(Cl.bool(true));

    // Queued, not active: a claim-rewards right now would still snapshot 0.
    expect(ro("get-active-fee-bips")).toBeUint(0);
    const pending = tupleFields(ro("get-pending-fees"));
    expect(num(pending["pending-bips"])).toBe(300);
    expect(num(pending["activation-cycle"])).toBe(start + 2);
    expect(num(pending["active-bips"])).toBe(0);

    // One cycle later it is still not active -- stakers still have time to go.
    mineCycles(1);
    expect(currentCycle(deployer, POX5)).toBe(start + 1);
    expect(ro("get-active-fee-bips")).toBeUint(0);

    // Two cycles after queueing, it takes effect.
    mineCycles(1);
    expect(currentCycle(deployer, POX5)).toBe(start + 2);
    expect(ro("get-active-fee-bips")).toBeUint(300);
  });

  it("applies a decrease immediately", () => {
    tx("update-fees", [Cl.uint(400)], deployer);
    mineCycles(2);
    expect(ro("get-active-fee-bips")).toBeUint(400);

    expect(tx("update-fees", [Cl.uint(100)], deployer)).toBeOk(Cl.bool(true));
    expect(ro("get-active-fee-bips")).toBeUint(100);
  });

  it("does not resurrect the pre-pending rate when a second change is queued", () => {
    tx("update-fees", [Cl.uint(200)], deployer);
    mineCycles(2);
    expect(ro("get-active-fee-bips")).toBeUint(200);

    // Queue a further increase; the matured 200 must stay active meanwhile.
    tx("update-fees", [Cl.uint(500)], deployer);
    expect(ro("get-active-fee-bips")).toBeUint(200);
    mineCycles(2);
    expect(ro("get-active-fee-bips")).toBeUint(500);
  });

  it("still caps the rate, now inclusive of 5%", () => {
    expect(tx("update-fees", [Cl.uint(500)], deployer)).toBeOk(Cl.bool(true));
    expect(tx("update-fees", [Cl.uint(501)], deployer)).toBeErr(
      Cl.uint(ERR_INVALID_FEES_BIPS),
    );
    expect(tx("update-fees", [Cl.uint(100)], other)).toBeErr(
      Cl.uint(ERR_UNAUTHORIZED_ADMIN),
    );
  });
});

describe("payout config", () => {
  it("rejects a min-claim that does not clear max-fee + dust", () => {
    expect(setPayoutConfig(100, 100 + DUST_LIMIT)).toBeErr(
      Cl.uint(ERR_INVALID_MIN_CLAIM),
    );
    expect(setPayoutConfig(100, 100 + DUST_LIMIT + 1)).toBeOk(Cl.bool(true));
  });

  it("lets a staker set and clear their own config without touching pox-5", () => {
    expect(setPayoutConfig(100, 1000)).toBeOk(Cl.bool(true));
    const config = tupleFields(
      (ro("get-payout-config", [Cl.principal(staker)]) as any).value,
    );
    expect(num(config["max-fee"])).toBe(100);
    expect(num(config["min-claim"])).toBe(1000);

    expect(tx("clear-payout-config", [], staker)).toBeOk(Cl.bool(true));
    expect(ro("get-payout-config", [Cl.principal(staker)])).toBeNone();
  });
});

describe("claim gating", () => {
  it("blocks a third party below min-claim but lets the staker through", () => {
    const { cycle, gross } = earnRewards(2_000);
    expect(gross).toBeGreaterThan(0);

    // A floor above the actual reward: only the staker may claim.
    expect(setPayoutConfig(100, gross + 1_000)).toBeOk(Cl.bool(true));
    expect(claim(cycle, other)).toBeErr(Cl.uint(ERR_BELOW_MIN_CLAIM));

    // The staker themselves is never gated by their own floor.
    expect(claim(cycle, staker).type).toBe("ok");
  });

  it("allows a third party once the reward clears min-claim", () => {
    const { cycle, gross } = earnRewards(2_000);
    expect(setPayoutConfig(100, 100 + DUST_LIMIT + 1)).toBeOk(Cl.bool(true));
    expect(gross).toBeGreaterThan(100 + DUST_LIMIT + 1);
    expect(claim(cycle, other).type).toBe("ok");
  });

  it("fails with ERR_BELOW_DUST_LIMIT, not an opaque sBTC error", () => {
    // Regression for v1: `earned - max-fee` under the sBTC dust limit made the
    // claim revert with sBTC's `(err u502)` and left the staker permanently
    // stuck. v2 rejects it up front with its own code.
    const { cycle, gross } = earnRewards(700);
    const maxFee = gross - DUST_LIMIT; // amount lands exactly on the dust limit
    expect(setPayoutConfig(maxFee, gross + 1)).toBeOk(Cl.bool(true));

    // The staker is not gated by min-claim, so this reaches the dust check.
    expect(claim(cycle, staker)).toBeErr(Cl.uint(ERR_BELOW_DUST_LIMIT));

    // And the reward is still there -- nothing was consumed.
    expect(
      num(ro("get-unclaimed-rewards-for-cycle", [Cl.uint(cycle), Cl.none()])),
    ).toBe(gross);

    // Clearing the config lets them take it as sBTC instead of being stuck.
    expect(tx("clear-payout-config", [], staker)).toBeOk(Cl.bool(true));
    const before = sbtcBalance(staker);
    expect(claim(cycle, staker).type).toBe("ok");
    expect(sbtcBalance(staker) - before).toBe(gross);
  });
});

describe("accepted-withdrawal fee refunds go to the staker", () => {
  it("credits the unused fee budget to the staker, not the admin", () => {
    const maxFee = 500;
    const actualFee = 30;
    const dust = maxFee - actualFee;

    const { cycle, gross } = earnRewards(50_000);
    expect(setPayoutConfig(maxFee, maxFee + DUST_LIMIT + 1)).toBeOk(
      Cl.bool(true),
    );
    expect(claim(cycle, other).type).toBe("ok");
    expect(num(ro("get-withdrawal-liability"))).toBe(gross);

    const height = simnet.burnBlockHeight - 1;
    expectOk(
      simnet.callPublicFn(
        `${SBTC}.sbtc-withdrawal`,
        "accept-withdrawal-request",
        [
          Cl.uint(1),
          Cl.buffer(new Uint8Array(32)),
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(actualFee),
          Cl.buffer(burnHeader(height)),
          Cl.uint(height),
          Cl.buffer(new Uint8Array(32)),
        ],
        SBTC_SIGNER,
      ).result,
      "accept-withdrawal-request",
    );
    expect(sbtcBalance(manager())).toBe(dust);

    // Settling credits the dust to the staker and releases the liability.
    expect(tx("settle-accepted-withdrawal", [Cl.uint(1)], other)).toBeOk(
      Cl.uint(dust),
    );
    expect(num(ro("get-withdrawal-liability"))).toBe(0);
    expect(num(ro("get-staker-refund", [Cl.principal(staker)]))).toBe(dust);

    // The admin cannot sweep it -- it is reserved.
    expect(tx("sweep-fee-refunds", [Cl.principal(dave)], deployer)).toBeErr(
      Cl.uint(ERR_NO_REFUNDS),
    );

    // The staker gets it. Anyone may trigger the payout.
    const before = sbtcBalance(staker);
    expect(tx("claim-refund", [Cl.principal(staker)], other)).toBeOk(
      Cl.uint(dust),
    );
    expect(sbtcBalance(staker) - before).toBe(dust);
    expect(sbtcBalance(manager())).toBe(0);
    expect(tx("claim-refund", [Cl.principal(staker)], other)).toBeErr(
      Cl.uint(ERR_NO_REFUND_CREDIT),
    );
  });
});

describe("admin hardening", () => {
  beforeEach(() => {
    expect(ro("get-admin-count")).toBeUint(1);
  });

  it("refuses to remove the last admin", () => {
    expect(
      tx("update-admin", [Cl.principal(deployer), Cl.bool(false)], deployer),
    ).toBeErr(Cl.uint(ERR_LAST_ADMIN));
    expect(ro("is-admin", [Cl.principal(deployer)])).toBeBool(true);
  });

  it("allows removal once a second admin exists", () => {
    expect(
      tx("update-admin", [Cl.principal(dave), Cl.bool(true)], deployer),
    ).toBeOk(Cl.principal(dave));
    expect(ro("get-admin-count")).toBeUint(2);

    expect(
      tx("update-admin", [Cl.principal(deployer), Cl.bool(false)], deployer),
    ).toBeOk(Cl.principal(deployer));
    expect(ro("get-admin-count")).toBeUint(1);
    expect(ro("is-admin", [Cl.principal(deployer)])).toBeBool(false);

    // ...and the demoted admin really has lost access.
    expect(tx("update-fees", [Cl.uint(10)], deployer)).toBeErr(
      Cl.uint(ERR_UNAUTHORIZED_ADMIN),
    );
  });

  it("does not double-count a repeated grant", () => {
    tx("update-admin", [Cl.principal(dave), Cl.bool(true)], deployer);
    tx("update-admin", [Cl.principal(dave), Cl.bool(true)], deployer);
    expect(ro("get-admin-count")).toBeUint(2);
  });

  it("rejects register-self for a contract other than itself", () => {
    expect(
      simnet.callPublicFn(
        MANAGER,
        "register-self",
        [
          Cl.principal(`${deployer}.signer-manager`),
          Cl.buffer(new Uint8Array(33)),
          Cl.uint(1),
          Cl.buffer(new Uint8Array(65)),
        ],
        deployer,
      ).result,
    ).toBeErr(Cl.uint(ERR_NOT_SELF));
  });
});

describe("per-cycle reward reserves", () => {
  it("cannot fund a claim for one cycle out of another cycle's reserve", () => {
    const { cycle, gross } = earnRewards(2_000);
    expect(
      num(ro("get-unclaimed-rewards-for-cycle", [Cl.uint(cycle), Cl.none()])),
    ).toBeGreaterThanOrEqual(gross);

    // A cycle the manager never pulled has an empty bucket, so a claim against
    // it is refused even though the contract holds sBTC for `cycle`.
    expect(claim(cycle + 5, staker)).toBeErr(
      Cl.uint(ERR_NO_CLAIMABLE_REWARDS),
    );
  });

  it("leaves the rounding residue in the contract, out of admin reach", () => {
    // pox-5 divides the pot per staker with integer division, so a few sats of
    // every cycle can never be claimed by anyone. They must stay in the
    // contract: there is deliberately no path that moves them to an admin.
    const { cycle, gross } = earnRewards(2_000);
    const pot = num(
      ro("get-unclaimed-rewards-for-cycle", [Cl.uint(cycle), Cl.none()]),
    );

    expect(claim(cycle, staker).type).toBe("ok");

    const residue = num(
      ro("get-unclaimed-rewards-for-cycle", [Cl.uint(cycle), Cl.none()]),
    );
    expect(residue).toBe(pot - gross);
    expect(num(ro("get-unclaimed-staker-rewards"))).toBe(residue);

    // Whatever the residue is, it is still held by the contract...
    expect(sbtcBalance(manager())).toBeGreaterThanOrEqual(residue);
    // ...it is reserved, so the admin cannot sweep it...
    expect(tx("sweep-fee-refunds", [Cl.principal(dave)], deployer)).toBeErr(
      Cl.uint(ERR_NO_REFUNDS),
    );
    // ...and it is not counted as fees, so it cannot be withdrawn either.
    expect(num(ro("get-earned-fees"))).toBe(0);
    expect(
      tx("withdraw-fees", [Cl.uint(1), Cl.principal(dave)], deployer),
    ).toBeErr(Cl.uint(ERR_INSUFFICIENT_FEES));
  });
});
