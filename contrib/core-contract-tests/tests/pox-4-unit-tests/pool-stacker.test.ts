import { beforeEach, describe, expect, it } from "vitest";
import {
  ERRORS,
  POX_CONTRACT,
  allowContractCaller,
  checkDelegateStxEvent,
  delegateStx,
  stackers,
} from "./helpers";
import { Cl } from "@stacks/transactions";
import { poxAddressToTuple } from "@stacks/stacking";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const address1 = accounts.get("wallet_1")!;
const address2 = accounts.get("wallet_2")!;
const address3 = accounts.get("wallet_3")!;
const initial_balance = 100000000000000n;

beforeEach(() => {
  simnet.setEpoch("3.0");
});

describe("test `delegate-stx`", () => {
  const amount = 1000000;
  const untilBurnHeight = 1000;

  it("Returns `(ok true)` on success", () => {
    const delegateResponse = delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));
  });

  it("Can omit the `until-burn-ht`", () => {
    const delegateResponse = delegateStx(
      amount,
      address2,
      null,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));
  });

  it("Can omit the `pox-addr`", () => {
    const delegateResponse = delegateStx(
      amount,
      address2,
      null,
      null,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));
  });

  it("Emits the correct event on success", () => {
    const delegateResponse = delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.events).toHaveLength(1);
    let event = delegateResponse.events[0];
    checkDelegateStxEvent(
      event,
      address1,
      initial_balance,
      0n,
      0n,
      BigInt(amount),
      address2,
      stackers[0].btcAddr,
      BigInt(untilBurnHeight)
    );
  });

  it("Fails if the account is already delegated", () => {
    let delegateResponse = delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    delegateResponse = delegateStx(
      amount,
      address3,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_ALREADY_DELEGATED)
    );
  });

  it("Fails if called indirectly through an unapproved contract", () => {
    const delegateStxArgs = [
      Cl.uint(amount),
      Cl.principal(address2),
      Cl.none(),
      Cl.none(),
    ];

    const delegateResponse = simnet.callPublicFn(
      "indirect",
      "delegate-stx",
      delegateStxArgs,
      address1
    );

    expect(delegateResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("Can be called indirectly through an approved contract", () => {
    allowContractCaller(`${deployer}.indirect`, null, address1);

    const delegateStxArgs = [
      Cl.uint(amount),
      Cl.principal(address2),
      Cl.none(),
      Cl.none(),
    ];

    const delegateResponse = simnet.callPublicFn(
      "indirect",
      "delegate-stx",
      delegateStxArgs,
      address1
    );

    expect(delegateResponse.result).toBeOk(Cl.bool(true));
  });

  it("Fails if the pox address is invalid", () => {
    let poxAddr = poxAddressToTuple(stackers[0].btcAddr);
    poxAddr.data["version"] = Cl.bufferFromHex("0a");
    const delegateStxArgs = [
      Cl.uint(amount),
      Cl.principal(address2),
      Cl.none(),
      Cl.some(poxAddr),
    ];

    const delegateResponse = simnet.callPublicFn(
      POX_CONTRACT,
      "delegate-stx",
      delegateStxArgs,
      address1
    );

    expect(delegateResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_INVALID_POX_ADDRESS)
    );
  });
});
