import { assert, beforeEach, describe, expect, it } from "vitest";

import { Cl } from "@stacks/transactions";
import { Pox4SignatureTopic, poxAddressToTuple } from "@stacks/stacking";
import {
  ERRORS,
  POX_CONTRACT,
  delegateStackStx,
  delegateStx,
  getStackingMinimum,
  stackers,
} from "./helpers";

const accounts = simnet.getAccounts();
const address1 = accounts.get("wallet_1")!;
const address2 = accounts.get("wallet_2")!;

beforeEach(() => {
  simnet.setEpoch("3.0");
});

describe("test `get-check-delegation`", () => {
  it("returns none when principal is not delegated", () => {
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-check-delegation",
      [Cl.principal(address1)],
      address1
    );
    expect(response.result).toBeNone();
  });

  it("returns info after delegation", () => {
    const amount = getStackingMinimum() * 1.2;

    const untilBurnHeight = 10;
    const delegateResponse = delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.events).toHaveLength(1);
    expect(delegateResponse.result).toBeOk(Cl.bool(true));

    const delegateInfo = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-check-delegation",
      [Cl.principal(address1)],
      address1
    );
    expect(delegateInfo.result).toBeSome(
      Cl.tuple({
        "amount-ustx": Cl.uint(amount),
        "delegated-to": Cl.principal(
          "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG"
        ),
        "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
        "until-burn-ht": Cl.some(Cl.uint(untilBurnHeight)),
      })
    );
  });

  it("does not expire if no burn height limit is set", () => {
    const amount = getStackingMinimum() * 1.2;

    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);

    const delegateInfo = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-check-delegation",
      [Cl.principal(address1)],
      address1
    );

    simnet.mineEmptyBlocks(10_000);
    expect(delegateInfo.result).toBeSome(
      Cl.tuple({
        "amount-ustx": Cl.uint(amount),
        "delegated-to": Cl.principal(
          "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG"
        ),
        "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
        "until-burn-ht": Cl.none(),
      })
    );
  });

  it("returns none after burn height expiration", () => {
    const amount = getStackingMinimum() * 1.2;
    simnet.mineEmptyBlock();

    const untilBurnHeight = 10;
    delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );

    simnet.mineEmptyBlocks(2 + untilBurnHeight - simnet.blockHeight);
    // a stacks block height of 12 means a burnchain block height of 11
    assert(simnet.blockHeight === 12);

    const delegateInfo = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-check-delegation",
      [Cl.principal(address1)],
      address1
    );
    expect(delegateInfo.result).toBeNone();
  });
});

describe("test `delegate-stack-stx`", () => {
  it("does not delegate if principal is not delegated", () => {
    const amount = getStackingMinimum() * 1.2;
    const { result } = delegateStackStx(
      address2,
      amount,
      stackers[0].btcAddr,
      1000,
      6,
      address1
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED));
  });

  it("can call delegate-stack-stx", () => {
    const amount = getStackingMinimum() * 1.2;
    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    const { result } = delegateStackStx(
      address1,
      amount,
      stackers[0].btcAddr,
      1000,
      6,
      address2
    );
    expect(result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(amount),
        stacker: Cl.principal(address1),
        "unlock-burn-height": Cl.uint(7350),
      })
    );
  });
});

describe("test `stack-aggregation-commit-indexed`", () => {
  it("returns `(ok uint)` on success", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 1.2;
    const maxAmount = amount * 2;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    const { result } = delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );
    expect(result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(amount),
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(7350),
      })
    );

    const poxAddr = poxAddressToTuple(account.btcAddr);
    const rewardCycle = 1;
    const period = 1;
    const authId = 1;
    const sigArgs = {
      authId,
      maxAmount,
      rewardCycle,
      period,
      topic: Pox4SignatureTopic.AggregateCommit,
      poxAddress: account.btcAddr,
      signerPrivateKey: account.signerPrivKey,
    };
    const signerSignature = account.client.signPoxSignature(sigArgs);
    const signerKey = Cl.bufferFromHex(account.signerPubKey);
    const response = simnet.callPublicFn(
      POX_CONTRACT,
      "stack-aggregation-commit-indexed",
      [
        poxAddr,
        Cl.uint(rewardCycle),
        Cl.some(Cl.bufferFromHex(signerSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ],
      address2
    );
    expect(response.result).toBeOk(Cl.uint(0));
  });
});
