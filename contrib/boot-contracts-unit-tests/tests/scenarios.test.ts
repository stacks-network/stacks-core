import { beforeEach, describe, expect, it } from "vitest";
import {
  ERRORS,
  delegateStackExtend,
  delegateStackIncrease,
  delegateStackStx,
  delegateStx,
  getPoxInfo,
  getStackingMinimum,
  revokeDelegateStx,
  stackers,
} from "./helpers";
import { Cl } from "@stacks/transactions";
import { poxAddressToTuple } from "@stacks/stacking";

const accounts = simnet.getAccounts();
const address1 = accounts.get("wallet_1")!;
const address2 = accounts.get("wallet_2")!;
const address3 = accounts.get("wallet_3")!;

beforeEach(() => {
  simnet.setEpoch("3.0");
});

describe("switching delegates`", () => {
  it("is allowed while stacked", () => {
    const amount = getStackingMinimum() * 2n;

    // Delegate to address2
    let delegateResponse = delegateStx(
      amount,
      address2,
      null,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));

    // Address2 stacks
    const { result } = delegateStackStx(
      address1,
      amount,
      stackers[0].btcAddr,
      simnet.blockHeight,
      4,
      address2
    );
    expect(result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(amount),
        stacker: Cl.principal(address1),
        "unlock-burn-height": Cl.uint(5250),
      })
    );

    // Revoke delegation to address2
    const revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeOk(
      Cl.some(
        Cl.tuple({
          "amount-ustx": Cl.uint(amount),
          "delegated-to": Cl.principal(address2),
          "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
          "until-burn-ht": Cl.none(),
        })
      )
    );

    // Delegate to address3
    delegateResponse = delegateStx(
      amount,
      address3,
      null,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));
  });

  it("revoked delegate cannot extend or increase", () => {
    const stackingMinimum = getStackingMinimum();
    const amount = stackingMinimum * 2n;

    // Delegate to address2
    let delegateResponse = delegateStx(
      amount,
      address2,
      null,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));

    // Address2 stacks
    const { result } = delegateStackStx(
      address1,
      stackingMinimum,
      stackers[0].btcAddr,
      simnet.blockHeight,
      2,
      address2
    );
    expect(result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(stackingMinimum),
        stacker: Cl.principal(address1),
        "unlock-burn-height": Cl.uint(3150),
      })
    );

    // Revoke delegation to address2
    const revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeOk(
      Cl.some(
        Cl.tuple({
          "amount-ustx": Cl.uint(amount),
          "delegated-to": Cl.principal(address2),
          "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
          "until-burn-ht": Cl.none(),
        })
      )
    );

    // Delegate to address3
    delegateResponse = delegateStx(
      amount,
      address3,
      null,
      stackers[1].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));

    // Address2 tries to extend
    let extendResponse = delegateStackExtend(
      address1,
      stackers[0].btcAddr,
      1n,
      address2
    );
    expect(extendResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );

    // Address2 tries to increase
    let increaseResponse = delegateStackIncrease(
      address1,
      stackers[0].btcAddr,
      100n,
      address2
    );
    expect(increaseResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("new delegate cannot lock before previous delegation unlocks", () => {
    const stackingMinimum = getStackingMinimum();
    const amount = stackingMinimum * 2n;
    const poxInfo = getPoxInfo();
    let unlockHeight = poxInfo.rewardCycleLength * 3n;

    // Delegate to address2
    let delegateResponse = delegateStx(
      amount,
      address2,
      null,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));

    // Address2 stacks
    let delegateStackStxResponse = delegateStackStx(
      address1,
      stackingMinimum,
      stackers[0].btcAddr,
      simnet.blockHeight,
      2,
      address2
    );
    expect(delegateStackStxResponse.result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(stackingMinimum),
        stacker: Cl.principal(address1),
        "unlock-burn-height": Cl.uint(unlockHeight),
      })
    );

    // Revoke delegation to address2
    const revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeOk(
      Cl.some(
        Cl.tuple({
          "amount-ustx": Cl.uint(amount),
          "delegated-to": Cl.principal(address2),
          "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
          "until-burn-ht": Cl.none(),
        })
      )
    );

    // Delegate to address3
    delegateResponse = delegateStx(
      amount,
      address3,
      null,
      stackers[1].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));

    // Address3 tries to re-stack
    delegateStackStxResponse = delegateStackStx(
      address1,
      stackingMinimum,
      stackers[1].btcAddr,
      simnet.blockHeight,
      2,
      address3
    );
    expect(delegateStackStxResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_ALREADY_STACKED)
    );

    // Address3 can stack after unlock
    simnet.mineEmptyBlocks(Number(unlockHeight) - simnet.blockHeight + 1);
    unlockHeight = poxInfo.rewardCycleLength * 6n;

    delegateStackStxResponse = delegateStackStx(
      address1,
      stackingMinimum + 2n,
      stackers[1].btcAddr,
      simnet.blockHeight,
      2,
      address3
    );
    expect(delegateStackStxResponse.result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(stackingMinimum + 2n),
        stacker: Cl.principal(address1),
        "unlock-burn-height": Cl.uint(unlockHeight),
      })
    );
  });

  it("New delegate cannot extend or increase", () => {
    const stackingMinimum = getStackingMinimum();
    const amount = stackingMinimum * 2n;

    // Delegate to address2
    let delegateResponse = delegateStx(
      amount,
      address2,
      null,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));

    // Address2 stacks
    const { result } = delegateStackStx(
      address1,
      stackingMinimum,
      stackers[0].btcAddr,
      simnet.blockHeight,
      2,
      address2
    );
    expect(result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(stackingMinimum),
        stacker: Cl.principal(address1),
        "unlock-burn-height": Cl.uint(3150),
      })
    );

    // Revoke delegation to address2
    const revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeOk(
      Cl.some(
        Cl.tuple({
          "amount-ustx": Cl.uint(amount),
          "delegated-to": Cl.principal(address2),
          "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
          "until-burn-ht": Cl.none(),
        })
      )
    );

    // Delegate to address3
    delegateResponse = delegateStx(
      amount,
      address3,
      null,
      stackers[1].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));

    // Address3 tries to extend to same pox address
    let extendResponse = delegateStackExtend(
      address1,
      stackers[0].btcAddr,
      1n,
      address3
    );
    expect(extendResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );

    // Address3 tries to extend to new pox address
    extendResponse = delegateStackExtend(
      address1,
      stackers[1].btcAddr,
      1n,
      address3
    );
    expect(extendResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );

    // Address3 tries to increase with same pox address
    let increaseResponse = delegateStackIncrease(
      address1,
      stackers[0].btcAddr,
      100n,
      address3
    );
    expect(increaseResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );

    // Address3 tries to increase with new pox address
    increaseResponse = delegateStackIncrease(
      address1,
      stackers[1].btcAddr,
      100n,
      address3
    );
    expect(increaseResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });
});
