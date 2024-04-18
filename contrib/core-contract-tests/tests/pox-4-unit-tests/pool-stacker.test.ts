import { beforeEach, describe, expect, it } from "vitest";
import {
  ERRORS,
  POX_CONTRACT,
  allowContractCaller,
  checkDelegateStxEvent,
  delegateStx,
  disallowContractCaller,
  revokeDelegateStx,
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

describe("delegate-stx", () => {
  const amount = 1000000;
  const untilBurnHeight = 1000;

  it("returns `(ok true)` on success", () => {
    const delegateResponse = delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));
  });

  it("can omit the `until-burn-ht`", () => {
    const delegateResponse = delegateStx(
      amount,
      address2,
      null,
      stackers[0].btcAddr,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));
  });

  it("can omit the `pox-addr`", () => {
    const delegateResponse = delegateStx(
      amount,
      address2,
      null,
      null,
      address1
    );
    expect(delegateResponse.result).toBeOk(Cl.bool(true));
  });

  it("emits the correct event on success", () => {
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

  it("fails if the account is already delegated", () => {
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

  it("fails if called indirectly through an unapproved contract", () => {
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

  it("can be called indirectly through an approved contract", () => {
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

  it("fails if the pox address version is invalid", () => {
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

  it("fails if the pox address hashbytes is invalid", () => {
    let poxAddr = poxAddressToTuple(stackers[0].btcAddr);
    poxAddr.data["hashbytes"] = Cl.bufferFromHex("deadbeef");
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

describe("revoke-delegate-stx", () => {
  it("returns prior state on success", () => {
    const amount = 1000000;
    const untilBurnHeight = 123;
    delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    const revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeOk(
      Cl.some(
        Cl.tuple({
          "amount-ustx": Cl.uint(amount),
          "delegated-to": Cl.principal(address2),
          "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
          "until-burn-ht": Cl.some(Cl.uint(untilBurnHeight)),
        })
      )
    );
  });

  it("fails if the account is not delegated", () => {
    const revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_DELEGATION_ALREADY_REVOKED)
    );
  });

  it("fails if the delegation was already revoked", () => {
    const amount = 1000000;
    const untilBurnHeight = 123;
    delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );

    // First revoke passes
    let revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeOk(
      Cl.some(
        Cl.tuple({
          "amount-ustx": Cl.uint(amount),
          "delegated-to": Cl.principal(address2),
          "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
          "until-burn-ht": Cl.some(Cl.uint(untilBurnHeight)),
        })
      )
    );

    // Second revoke fails
    revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_DELEGATION_ALREADY_REVOKED)
    );
  });

  it("fails if the delegation has expired", () => {
    const amount = 1000000;
    const untilBurnHeight = 3;
    delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    while (simnet.blockHeight <= untilBurnHeight) {
      simnet.mineEmptyBlock();
    }
    const revokeResponse = revokeDelegateStx(address1);
    expect(revokeResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_DELEGATION_ALREADY_REVOKED)
    );
  });

  it("fails when called by unapproved caller", () => {
    const revokeResponse = simnet.callPublicFn(
      "indirect",
      "revoke-delegate-stx",
      [],
      address1
    );

    expect(revokeResponse.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("passes when called by approved caller", () => {
    const amount = 1000000;
    const untilBurnHeight = 123;

    delegateStx(
      amount,
      address2,
      untilBurnHeight,
      stackers[0].btcAddr,
      address1
    );
    allowContractCaller(`${deployer}.indirect`, null, address1);

    const revokeResponse = simnet.callPublicFn(
      "indirect",
      "revoke-delegate-stx",
      [],
      address1
    );

    expect(revokeResponse.result).toBeOk(
      Cl.some(
        Cl.tuple({
          "amount-ustx": Cl.uint(amount),
          "delegated-to": Cl.principal(address2),
          "pox-addr": Cl.some(poxAddressToTuple(stackers[0].btcAddr)),
          "until-burn-ht": Cl.some(Cl.uint(untilBurnHeight)),
        })
      )
    );
  });
});

describe("allow-contract-caller", () => {
  it("returns `(ok true)` on success", () => {
    const response = allowContractCaller(
      `${deployer}.indirect`,
      null,
      address1
    );
    expect(response.result).toBeOk(Cl.bool(true));
  });

  it("cannot be called indirectly", () => {
    const response = simnet.callPublicFn(
      "indirect",
      "allow-contract-caller",
      [Cl.principal(`${deployer}.indirect`), Cl.none()],
      address1
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });
});

describe("disallow-contract-caller", () => {
  it("returns `(ok true)` on success", () => {
    allowContractCaller(`${deployer}.indirect`, null, address1);
    const response = disallowContractCaller(`${deployer}.indirect`, address1);
    expect(response.result).toBeOk(Cl.bool(true));
  });

  it("cannot be called indirectly", () => {
    const response = simnet.callPublicFn(
      "indirect",
      "disallow-contract-caller",
      [Cl.principal(`${deployer}.indirect`)],
      address1
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("cannot be called indirectly, even by an approved caller", () => {
    allowContractCaller(`${deployer}.indirect`, null, address1);
    const response = simnet.callPublicFn(
      "indirect",
      "disallow-contract-caller",
      [Cl.principal(`${deployer}.indirect`)],
      address1
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("returns `(ok false)` if the caller was not allowed", () => {
    const response = disallowContractCaller(`${deployer}.indirect`, address1);
    expect(response.result).toBeOk(Cl.bool(false));
  });
});
