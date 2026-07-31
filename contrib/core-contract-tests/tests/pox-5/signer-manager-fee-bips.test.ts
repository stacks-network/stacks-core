// Pins the two fee constants of `contracts/signer-manager.clar`:
//
//   MAX_BIPS          u10000  -- the bound enforced by `update-fees` (`<`, so
//                               the highest settable rate is 9999 bips, i.e.
//                               99.99%)
//   BIPS_DENOMINATOR  u10000  -- the divisor used when fees are taken from
//                               rewards (`gross * bips / 10000`)
//
// v1 is deliberately UNCAPPED: an admin of this contract may take essentially
// all of a staker's rewards, and `MAX_BIPS` exists only to keep the rate a
// fraction of the denominator rather than to limit it. A staker's protection is
// choosing which signer to stake with, not a contract-enforced ceiling. The
// v2 reference contract (`signer-manager-v2.clar`) is the one that caps fees,
// at 5% -- see signer-manager-v2*.test.ts.
//
// So what these pin is: the rate can never reach 100% of rewards, and the
// denominator is 10000. A wrong denominator would silently rescale every fee
// (e.g. /1000 turns 499 bips into ~50%). The first block covers the bound, the
// second drives a real reward payout and checks the arithmetic against the
// gross rewards pox-5 reports.
import { Cl } from "@stacks/transactions";
import { describe, expect, it } from "vitest";
import {
  currentCycle,
  expectOk,
  fundRewards,
  managerPrincipal,
  num,
  registerSigner,
  SBTC,
} from "./helpers/rewards-fixture";

// The STX-only signer manager (contracts/signer-manager.clar).
const MANAGER = "signer-manager";
// That contract is written against the mainnet pox-5 principal (its
// `authorize-pox-5` compares `contract-caller` to it), so the whole flow has to
// be driven through the mainnet-addressed boot copy, not the testnet one the
// other tests use.
const POX5 = "ST000000000000000000002AMW42H.pox-5";

const MAX_BIPS = 10_000;
const BIPS_DENOMINATOR = 10_000;
const ERR_INVALID_FEES_BIPS = 1005;

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!; // admin: `(map-set admins tx-sender true)` at deploy
const staker = accounts.get("wallet_1")!;

const updateFees = (bips: number, sender = deployer) =>
  simnet.callPublicFn(MANAGER, "update-fees", [Cl.uint(bips)], sender).result;

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

describe("update-fees enforces MAX_BIPS", () => {
  it("accepts every rate below MAX_BIPS, up to 99.99%", () => {
    // Rates well past 5% are valid here by design -- v1 is uncapped.
    for (const bips of [0, 1, 100, 250, 500, 1_000, 5_000, MAX_BIPS - 1]) {
      expect(updateFees(bips)).toBeOk(Cl.bool(true));
      // sanity: everything accepted is still a proper fraction of the pot
      expect(bips / BIPS_DENOMINATOR).toBeLessThan(1);
    }
  });

  it("rejects MAX_BIPS itself and anything above it", () => {
    for (const bips of [
      MAX_BIPS, // exactly 100% -- the bound is `<`, not `<=`
      MAX_BIPS + 1,
      20_000,
    ]) {
      expect(updateFees(bips)).toBeErr(Cl.uint(ERR_INVALID_FEES_BIPS));
    }
  });

  it("leaves the stored rate untouched when a too-high rate is rejected", () => {
    expect(updateFees(MAX_BIPS - 1)).toBeOk(Cl.bool(true));
    expect(updateFees(MAX_BIPS)).toBeErr(Cl.uint(ERR_INVALID_FEES_BIPS));

    // The rate is only observable once snapshotted per cycle, so drive a claim.
    const { cycle } = earnRewards(MAX_BIPS - 1, { alreadySet: true });
    expect(feeBipsForCycle(cycle)).toBeUint(MAX_BIPS - 1);
  });
});

describe("fees are taken as bips / BIPS_DENOMINATOR", () => {
  // Each case runs on a fresh simnet (clarinet resets between tests), so the
  // same cycle can be replayed at a different rate.
  const cases: Array<[string, number]> = [
    ["0 bips takes nothing", 0],
    ["100 bips is exactly 1%", 100],
    ["250 bips is exactly 2.5%", 250],
    ["500 bips is exactly 5%", 500],
    // v1 permits rates a capped contract never would; the arithmetic must
    // hold there too, and the staker must still be left something.
    ["9999 bips (MAX_BIPS - 1) is 99.99%", MAX_BIPS - 1],
  ];

  for (const [name, bips] of cases) {
    it(name, () => {
      const { cycle, gross } = earnRewards(bips);
      expect(gross).toBeGreaterThan(0);
      expect(feeBipsForCycle(cycle)).toBeUint(bips);

      const expectedFee = Math.floor((gross * bips) / BIPS_DENOMINATOR);
      const view = simnet.callReadOnlyFn(
        MANAGER,
        "get-earned-staker-rewards",
        [Cl.principal(staker), Cl.uint(cycle), Cl.none()],
        deployer,
      ).result as any;

      expect(view.value.fees).toBeUint(expectedFee);
      expect(view.value.earned).toBeUint(gross - expectedFee);

      // The fee is a fraction of 10000, not of 100 or 1000: rounding aside,
      // `fee / gross` must equal `bips / 10000`.
      expect(expectedFee / gross).toBeCloseTo(bips / BIPS_DENOMINATOR, 6);
      // ...and can never reach 100% of the rewards, so a claim always leaves
      // the staker something. This is the only ceiling v1 has.
      expect(expectedFee * BIPS_DENOMINATOR).toBeLessThan(gross * MAX_BIPS);
      expect(gross - expectedFee).toBeGreaterThan(0);

      // The payout matches the view: staker gets `gross - fee`, the contract
      // keeps `fee` as withdrawable admin fees.
      const before = sbtcBalance(staker);
      const claim = simnet.callPublicFn(
        MANAGER,
        "claim-staker-rewards",
        [Cl.principal(staker), Cl.uint(cycle), Cl.none()],
        deployer,
      );
      expect(claim.result.type).toBe("ok");

      expect(sbtcBalance(staker) - before).toBe(gross - expectedFee);
      expect(
        simnet.callReadOnlyFn(MANAGER, "get-earned-fees", [], deployer).result,
      ).toBeUint(expectedFee);
    });
  }
});

const feeBipsForCycle = (cycle: number) =>
  simnet.callReadOnlyFn(
    MANAGER,
    "get-fee-bips-for-cycle",
    [Cl.uint(cycle), Cl.none()],
    deployer,
  ).result;

/**
 * Drive pox-5 to real, non-zero rewards for `staker` under `MANAGER` with
 * `fees-bips` set to `bips`, and have the manager pull the pot (which
 * snapshots the fee rate for the cycle).
 *
 * Returns the reward cycle and the gross (pre-fee) rewards pox-5 attributes
 * to the staker.
 */
function earnRewards(bips: number, opts: { alreadySet?: boolean } = {}) {
  const manager = managerPrincipal(deployer, MANAGER);
  expectOk(registerSigner(deployer, MANAGER, POX5).result, "register-self");

  if (!opts.alreadySet) {
    expect(updateFees(bips)).toBeOk(Cl.bool(true));
  }

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
        Cl.principal(manager),
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
  // `calculate-rewards` settles the cycle that has just ended, so move past it.
  const target = num(
    simnet.callReadOnlyFn(
      POX5,
      "reward-cycle-to-burn-height",
      [Cl.uint(rewardCycle + 1)],
      deployer,
    ).result,
  );
  simnet.mineEmptyBurnBlocks(Math.max(1, target - simnet.burnBlockHeight + 2));

  expectOk(fundRewards(staker, 50_000_000, POX5).result, "fund rewards");
  expectOk(
    simnet.callPublicFn(POX5, "calculate-rewards", [Cl.list([])], deployer)
      .result,
    "calculate-rewards",
  );

  // Pulls the sBTC pot into the manager and snapshots `fees-bips` for the
  // cycle. The signer's rewards-per-token -- and with it each staker's earned
  // amount -- is only settled here, so `gross` has to be read afterwards.
  expectOk(
    simnet.callPublicFn(
      MANAGER,
      "claim-rewards",
      [Cl.list([]), Cl.uint(rewardCycle)],
      deployer,
    ).result,
    "claim-rewards",
  );

  // Gross (pre-fee) rewards as pox-5 attributes them to the staker.
  const gross = num(
    simnet.callReadOnlyFn(
      POX5,
      "get-earned-staker-rewards",
      [
        Cl.principal(manager),
        Cl.uint(rewardCycle),
        Cl.none(),
        Cl.principal(staker),
      ],
      deployer,
    ).result,
  );

  return { cycle: rewardCycle, gross };
}
