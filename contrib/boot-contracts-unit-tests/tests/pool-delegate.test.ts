import { assert, beforeEach, describe, expect, it } from "vitest";

import {
  Cl,
  ClarityType,
  ResponseCV,
  SomeCV,
  TupleCV,
  UIntCV,
  cvToString,
} from "@stacks/transactions";
import { Pox4SignatureTopic, poxAddressToTuple } from "@stacks/stacking";
import {
  ERRORS,
  POX_CONTRACT,
  allowContractCaller,
  delegateStackExtend,
  delegateStackIncrease,
  delegateStackStx,
  delegateStx,
  getPoxInfo,
  getStackerInfo,
  getStackingMinimum,
  stackAggregationCommitIndexed,
  stackAggregationIncrease,
  stackStx,
  stackers,
} from "./helpers";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const address1 = accounts.get("wallet_1")!;
const address2 = accounts.get("wallet_2")!;
const address3 = accounts.get("wallet_3")!;

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
    const amount = getStackingMinimum() * 2n;

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
    const amount = getStackingMinimum() * 2n;

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
    const amount = getStackingMinimum() * 2n;
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

describe("test `get-delegation-info`", () => {
  it("returns none when principal is not delegated", () => {
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-delegation-info",
      [Cl.principal(address1)],
      address1
    );
    expect(response.result).toBeNone();
  });

  it("returns info after delegation", () => {
    const amount = getStackingMinimum() * 2n;

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
      "get-delegation-info",
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
    const amount = getStackingMinimum() * 2n;

    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);

    const delegateInfo = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-delegation-info",
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
    const amount = getStackingMinimum() * 2n;
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
      "get-delegation-info",
      [Cl.principal(address1)],
      address1
    );
    expect(delegateInfo.result).toBeNone();
  });
});

describe("test `get-allowance-contract-callers`", () => {
  it("returns `none` when not allowed", () => {
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-allowance-contract-callers",
      [Cl.principal(address1), Cl.contractPrincipal(deployer, "indirect")],
      address1
    );
    expect(response.result).toBeNone();
  });

  it("returns `(some none)` when allowed indefinitely", () => {
    allowContractCaller(`${deployer}.indirect`, null, address1);

    const delegateInfo = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-allowance-contract-callers",
      [Cl.principal(address1), Cl.contractPrincipal(deployer, "indirect")],
      address1
    );
    expect(delegateInfo.result).toBeSome(
      Cl.tuple({
        "until-burn-ht": Cl.none(),
      })
    );
  });

  it("returns `(some (some X))` when allowed until burn height X", () => {
    const untilBurnHeight = 10;
    allowContractCaller(`${deployer}.indirect`, untilBurnHeight, address1);

    const delegateInfo = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-allowance-contract-callers",
      [Cl.principal(address1), Cl.contractPrincipal(deployer, "indirect")],
      address1
    );
    expect(delegateInfo.result).toBeSome(
      Cl.tuple({
        "until-burn-ht": Cl.some(Cl.uint(untilBurnHeight)),
      })
    );
  });

  it("returns `none` when a different caller is allowed", () => {
    allowContractCaller(`${deployer}.not-indirect`, null, address1);
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-allowance-contract-callers",
      [Cl.principal(address1), Cl.contractPrincipal(deployer, "indirect")],
      address1
    );
    expect(response.result).toBeNone();
  });
});

describe("test `delegate-stack-stx`", () => {
  it("does not delegate if principal is not delegated", () => {
    const amount = getStackingMinimum() * 2n;
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
    const amount = getStackingMinimum() * 2n;
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

  it("returns an error for stacking too early", () => {
    const amount = getStackingMinimum() * 2n;
    const startBurnHeight = 3000;
    const lockPeriod = 6;
    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    const { result } = delegateStackStx(
      address1,
      amount,
      stackers[0].btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_INVALID_START_BURN_HEIGHT));
  });

  it("cannot be called indirectly by an unapproved caller", () => {
    const amount = getStackingMinimum() * 2n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;
    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);

    const response = simnet.callPublicFn(
      "indirect",
      "delegate-stack-stx",
      [
        Cl.principal(address1),
        Cl.uint(amount),
        poxAddressToTuple(stackers[0].btcAddr),
        Cl.uint(startBurnHeight),
        Cl.uint(lockPeriod),
      ],
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("can be called indirectly by an approved caller", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;
    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    allowContractCaller(`${deployer}.indirect`, null, address2);

    const response = simnet.callPublicFn(
      "indirect",
      "delegate-stack-stx",
      [
        Cl.principal(address1),
        Cl.uint(amount),
        poxAddressToTuple(account.btcAddr),
        Cl.uint(startBurnHeight),
        Cl.uint(lockPeriod),
      ],
      address2
    );
    expect(response.result).toBeOk(
      Cl.tuple({
        "lock-amount": Cl.uint(amount),
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(7350),
      })
    );
  });

  it("returns an error if not delegated", () => {
    const amount = getStackingMinimum() * 2n;
    const { result } = delegateStackStx(
      address1,
      amount,
      stackers[0].btcAddr,
      1000,
      6,
      address2
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED));
  });

  it("returns an error if delegated to someone else", () => {
    const amount = getStackingMinimum() * 2n;
    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    const { result } = delegateStackStx(
      address1,
      amount,
      stackers[0].btcAddr,
      1000,
      6,
      address3
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED));
  });

  it("returns an error if stacking more than delegated", () => {
    const amount = getStackingMinimum() * 2n;
    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    const { result } = delegateStackStx(
      address1,
      amount + 1n,
      stackers[0].btcAddr,
      1000,
      6,
      address2
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_DELEGATION_TOO_MUCH_LOCKED));
  });

  it("returns an error if stacking to a different pox address", () => {
    const amount = getStackingMinimum() * 2n;
    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    const { result } = delegateStackStx(
      address1,
      amount,
      stackers[1].btcAddr,
      1000,
      6,
      address2
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_DELEGATION_POX_ADDR_REQUIRED));
  });

  it("can call delegate-stack-stx when no pox address was set", () => {
    const amount = getStackingMinimum() * 2n;
    delegateStx(amount, address2, null, null, address1);
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

  it("returns an error if stacking beyond the delegation height", () => {
    const amount = getStackingMinimum() * 2n;
    delegateStx(amount, address2, 2000, stackers[0].btcAddr, address1);
    const { result } = delegateStackStx(
      address1,
      amount,
      stackers[0].btcAddr,
      1000,
      6,
      address2
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_DELEGATION_EXPIRES_DURING_LOCK));
  });

  it("returns an error if stacker is already stacked", () => {
    const stacker = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    delegateStackStx(
      address1,
      amount,
      stacker.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );
    const { result } = delegateStackStx(
      address1,
      amount,
      stacker.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_STACKING_ALREADY_STACKED));
  });

  it("returns an error if stacker does not have enough unlocked stacks", () => {
    const stacker = stackers[0];
    const amount =
      simnet.getAssetsMap().get("STX")?.get(stacker.stxAddress)! + 10n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    const { result } = delegateStackStx(
      address1,
      amount,
      stacker.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_STACKING_INSUFFICIENT_FUNDS));
  });

  it("returns an error if amount is 0", () => {
    const stacker = stackers[0];
    const amount = 0;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    delegateStx(amount, address2, null, stackers[0].btcAddr, address1);
    const { result } = delegateStackStx(
      address1,
      amount,
      stacker.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );
    expect(result).toBeErr(Cl.int(ERRORS.ERR_STACKING_INVALID_AMOUNT));
  });
});

describe("test `stack-aggregation-commit-indexed`", () => {
  it("returns `(ok uint)` on success", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
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

  it("returns an error when there is no partially stacked STX", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);

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
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL)
    );
  });

  it("returns an error when called by an unauthorized caller", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
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
      "indirect",
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
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("can be called indirectly by an authorized caller", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    allowContractCaller(`${deployer}.indirect`, null, address2);
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
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
      "indirect",
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

  it("returns an error when called with no signature or prior authorization", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    const poxAddr = poxAddressToTuple(account.btcAddr);
    const rewardCycle = 1;
    const authId = 1;
    const signerKey = Cl.bufferFromHex(account.signerPubKey);
    const response = simnet.callPublicFn(
      POX_CONTRACT,
      "stack-aggregation-commit-indexed",
      [
        poxAddr,
        Cl.uint(rewardCycle),
        Cl.none(),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ],
      address2
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_NOT_ALLOWED));
  });

  it("returns an error when the stacking threshold is not met", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() / 2n;
    const maxAmount = amount * 4n;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
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
    let response = simnet.callPublicFn(
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
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_THRESHOLD_NOT_MET)
    );
  });
});

describe("test `stack-aggregation-commit`", () => {
  it("returns `(ok uint)` on success", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
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
      "stack-aggregation-commit",
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
    expect(response.result).toBeOk(Cl.bool(true));
  });

  it("returns an error when there is no partially stacked STX", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);

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
      "stack-aggregation-commit",
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
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL)
    );
  });

  it("returns an error when called by an unauthorized caller", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
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
      "indirect",
      "stack-aggregation-commit",
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
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("can be called indirectly by an authorized caller", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    allowContractCaller(`${deployer}.indirect`, null, address2);
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
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
      "indirect",
      "stack-aggregation-commit",
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
    expect(response.result).toBeOk(Cl.bool(true));
  });

  it("returns an error when called with no signature or prior authorization", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    const poxAddr = poxAddressToTuple(account.btcAddr);
    const rewardCycle = 1;
    const authId = 1;
    const signerKey = Cl.bufferFromHex(account.signerPubKey);
    const response = simnet.callPublicFn(
      POX_CONTRACT,
      "stack-aggregation-commit",
      [
        poxAddr,
        Cl.uint(rewardCycle),
        Cl.none(),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ],
      address2
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_NOT_ALLOWED));
  });

  it("returns an error when the stacking threshold is not met", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() / 2n;
    const maxAmount = amount * 4n;
    delegateStx(amount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
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
    let response = simnet.callPublicFn(
      POX_CONTRACT,
      "stack-aggregation-commit",
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
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_THRESHOLD_NOT_MET)
    );
  });
});

describe("test `delegate-stack-increase`", () => {
  it("returns `(ok <stacker-state>)` on success", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    let response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "total-locked": Cl.uint(maxAmount),
      })
    );
  });

  it("can be called after committing", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;
    const rewardCycle = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    let response = stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );
    expect(response.result.type).toBe(ClarityType.ResponseOk);
    let index = ((response.result as ResponseCV).value as UIntCV).value;

    response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "total-locked": Cl.uint(maxAmount),
      })
    );

    // the amount in the reward set should not update until after
    // the delegator calls `stack-aggregation-increase`
    let info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    let tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(amount);

    response = stackAggregationIncrease(
      account,
      rewardCycle,
      index,
      maxAmount,
      authId,
      address2
    );
    expect(response.result).toBeOk(Cl.bool(true));

    // check that the amount was increased
    info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(maxAmount);
  });

  it("cannot be called if not delegated", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;

    // Arithmetic underflow is not caught gracefully, so this triggers a runtime error.
    // Preferably, it would return a `ERR_STACKING_NOT_DELEGATED` error.
    expect(() =>
      delegateStackIncrease(
        account.stxAddress,
        account.btcAddr,
        maxAmount - amount,
        address2
      )
    ).toThrow();
  });

  it("cannot be called if not stacked", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);

    // Arithmetic underflow is not caught gracefully, so this triggers a runtime error.
    // Preferably, it would return a `ERR_STACKING_NOT_DELEGATED` error.
    expect(() =>
      delegateStackIncrease(
        account.stxAddress,
        account.btcAddr,
        maxAmount - amount,
        address2
      )
    ).toThrow();
  });

  it("cannot be called in last cycle of delegation", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;
    const poxInfo = getPoxInfo();
    const cycleLength = Number(poxInfo.rewardCycleLength);

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    // mine enough blocks to reach the last cycle of the delegation
    simnet.mineEmptyBlocks(6 * cycleLength);

    let response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_INVALID_LOCK_PERIOD)
    );
  });

  it("cannot be called after delegation has expired", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;
    const poxInfo = getPoxInfo();
    const cycleLength = Number(poxInfo.rewardCycleLength);

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    // mine enough blocks to end the delegation
    simnet.mineEmptyBlocks(7 * cycleLength);

    // Arithmetic underflow is not caught gracefully, so this triggers a runtime error.
    // Preferably, it would return a `ERR_STACKING_NOT_DELEGATED` error.
    expect(() =>
      delegateStackIncrease(
        account.stxAddress,
        account.btcAddr,
        maxAmount - amount,
        address2
      )
    ).toThrow();
  });

  it("requires a positive increase amount", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    let response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      0,
      address2
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_STACKING_INVALID_AMOUNT));
  });

  it("cannot be called indirectly by an unauthorized caller", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    const delegateStackIncreaseArgs = [
      Cl.principal(account.stxAddress),
      poxAddressToTuple(account.btcAddr),
      Cl.uint(maxAmount - amount),
    ];
    let response = simnet.callPublicFn(
      "indirect",
      "delegate-stack-increase",
      delegateStackIncreaseArgs,
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("can be called indirectly by an authorized caller", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    allowContractCaller(`${deployer}.indirect`, null, address2);
    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    const delegateStackIncreaseArgs = [
      Cl.principal(account.stxAddress),
      poxAddressToTuple(account.btcAddr),
      Cl.uint(maxAmount - amount),
    ];
    let response = simnet.callPublicFn(
      "indirect",
      "delegate-stack-increase",
      delegateStackIncreaseArgs,
      address2
    );
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "total-locked": Cl.uint(maxAmount),
      })
    );
  });

  it("cannot be called for a solo stacker", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;
    const authId = 1;

    stackStx(
      account,
      amount,
      startBurnHeight,
      lockPeriod,
      maxAmount,
      authId,
      account.stxAddress
    );

    let response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_STACKING_NOT_DELEGATED));
  });

  it("can only be called by the delegate", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    let response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address3
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );
  });

  it("can increase to the total account balance", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;
    const balance = simnet.getAssetsMap().get("STX")?.get(account.stxAddress)!;

    delegateStx(balance, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    let response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      balance - amount,
      address2
    );
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "total-locked": Cl.uint(balance),
      })
    );
  });

  it("cannot increase to more than the total account balance", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;
    const balance = simnet.getAssetsMap().get("STX")?.get(account.stxAddress)!;

    delegateStx(balance, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    let response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      balance - amount + 1n,
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_INSUFFICIENT_FUNDS)
    );
  });

  it("cannot increase to more than the delegated amount", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const startBurnHeight = 1000;
    const lockPeriod = 6;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      startBurnHeight,
      lockPeriod,
      address2
    );

    let response = delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount,
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_DELEGATION_TOO_MUCH_LOCKED)
    );
  });
});

describe("test `stack-aggregation-increase`", () => {
  it("returns `(ok uint)` and increases stacked amount on success", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const rewardCycle = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    let response = stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );
    expect(response.result.type).toBe(ClarityType.ResponseOk);
    let index = ((response.result as ResponseCV).value as UIntCV).value;

    delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );

    // check the amount in the reward set
    let info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    let tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(amount);

    response = stackAggregationIncrease(
      account,
      rewardCycle,
      index,
      maxAmount,
      authId,
      address2
    );
    expect(response.result).toBeOk(Cl.bool(true));

    // check that the amount was increased
    info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(maxAmount);
  });

  it("cannot be called indirectly from unauthorized caller", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const rewardCycle = 1;
    const period = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    let response = stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );
    expect(response.result.type).toBe(ClarityType.ResponseOk);
    let index = ((response.result as ResponseCV).value as UIntCV).value;

    delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );

    const sigArgs = {
      authId,
      maxAmount,
      rewardCycle: Number(rewardCycle),
      period: Number(period),
      topic: Pox4SignatureTopic.AggregateIncrease,
      poxAddress: account.btcAddr,
      signerPrivateKey: account.signerPrivKey,
    };
    const signerSignature = account.client.signPoxSignature(sigArgs);
    const signerKey = Cl.bufferFromHex(account.signerPubKey);

    const args = [
      poxAddressToTuple(account.btcAddr),
      Cl.uint(rewardCycle),
      Cl.uint(index),
      Cl.some(Cl.bufferFromHex(signerSignature)),
      signerKey,
      Cl.uint(maxAmount),
      Cl.uint(authId),
    ];

    response = simnet.callPublicFn(
      "indirect",
      "stack-aggregation-increase",
      args,
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );

    // check that the amount was not increased
    const info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(amount);
  });

  it("can be called indirectly from an authorized caller", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const rewardCycle = 1;
    const period = 1;
    const authId = 1;

    allowContractCaller(`${deployer}.indirect`, null, address2);

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    let response = stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );
    expect(response.result.type).toBe(ClarityType.ResponseOk);
    let index = ((response.result as ResponseCV).value as UIntCV).value;

    delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );

    const sigArgs = {
      authId,
      maxAmount,
      rewardCycle: Number(rewardCycle),
      period: Number(period),
      topic: Pox4SignatureTopic.AggregateIncrease,
      poxAddress: account.btcAddr,
      signerPrivateKey: account.signerPrivKey,
    };
    const signerSignature = account.client.signPoxSignature(sigArgs);
    const signerKey = Cl.bufferFromHex(account.signerPubKey);

    const args = [
      poxAddressToTuple(account.btcAddr),
      Cl.uint(rewardCycle),
      Cl.uint(index),
      Cl.some(Cl.bufferFromHex(signerSignature)),
      signerKey,
      Cl.uint(maxAmount),
      Cl.uint(authId),
    ];

    response = simnet.callPublicFn(
      "indirect",
      "stack-aggregation-increase",
      args,
      address2
    );
    expect(response.result).toBeOk(Cl.bool(true));

    // check that the amount was increased
    const info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(maxAmount);
  });

  it("returns an error for current reward cycle", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const rewardCycle = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    let response = stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );
    expect(response.result.type).toBe(ClarityType.ResponseOk);
    let index = ((response.result as ResponseCV).value as UIntCV).value;

    delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );

    simnet.mineEmptyBlocks(1100);

    response = stackAggregationIncrease(
      account,
      rewardCycle,
      index,
      maxAmount,
      authId,
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_INVALID_LOCK_PERIOD)
    );

    // check that the amount was not increased
    const info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(amount);
  });

  it("returns an error for switching pox address", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const maxAmount = minAmount * 4n;
    const rewardCycle = 1;
    const period = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    let response = stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );
    expect(response.result.type).toBe(ClarityType.ResponseOk);
    let index = ((response.result as ResponseCV).value as UIntCV).value;

    delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );

    const sigArgs = {
      authId,
      maxAmount,
      rewardCycle: Number(rewardCycle),
      period: Number(period),
      topic: Pox4SignatureTopic.AggregateIncrease,
      poxAddress: stackers[1].btcAddr,
      signerPrivateKey: account.signerPrivKey,
    };
    const signerSignature = account.client.signPoxSignature(sigArgs);
    const signerKey = Cl.bufferFromHex(account.signerPubKey);

    const args = [
      poxAddressToTuple(stackers[1].btcAddr),
      Cl.uint(rewardCycle),
      Cl.uint(index),
      Cl.some(Cl.bufferFromHex(signerSignature)),
      signerKey,
      Cl.uint(maxAmount),
      Cl.uint(authId),
    ];
    response = simnet.callPublicFn(
      POX_CONTRACT,
      "stack-aggregation-increase",
      args,
      address2
    );
    // Note: I don't think it is possible to reach the `ERR_DELEGATION_WRONG_REWARD_SLOT` error
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_NO_SUCH_PRINCIPAL)
    );

    // check that the amount was not increased
    const info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(amount);
  });

  it("cannot increase more than the authorized amount", () => {
    const account = stackers[0];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const authAmount = minAmount * 3n;
    const maxAmount = minAmount * 4n;
    const rewardCycle = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    let response = stackAggregationCommitIndexed(
      account,
      rewardCycle,
      authAmount,
      authId,
      address2
    );
    expect(response.result.type).toBe(ClarityType.ResponseOk);
    let index = ((response.result as ResponseCV).value as UIntCV).value;

    delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );

    // check the amount in the reward set
    let info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    let tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(amount);

    response = stackAggregationIncrease(
      account,
      rewardCycle,
      index,
      authAmount,
      authId,
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH)
    );

    // check that the amount was not increased
    info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(amount);
  });

  it("cannot change signers", () => {
    const account = stackers[0];
    const account1 = stackers[1];
    const minAmount = getStackingMinimum();
    const amount = minAmount * 2n;
    const authAmount = minAmount * 3n;
    const maxAmount = minAmount * 4n;
    const rewardCycle = 1;
    const period = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    let response = stackAggregationCommitIndexed(
      account,
      rewardCycle,
      authAmount,
      authId,
      address2
    );
    expect(response.result.type).toBe(ClarityType.ResponseOk);
    let index = ((response.result as ResponseCV).value as UIntCV).value;

    delegateStackIncrease(
      account.stxAddress,
      account.btcAddr,
      maxAmount - amount,
      address2
    );

    const sigArgs = {
      authId,
      maxAmount,
      rewardCycle: Number(rewardCycle),
      period: Number(period),
      topic: Pox4SignatureTopic.AggregateIncrease,
      poxAddress: account.btcAddr,
      signerPrivateKey: account1.signerPrivKey,
    };
    const signerSignature = account1.client.signPoxSignature(sigArgs);
    const signerKey = Cl.bufferFromHex(account1.signerPubKey);

    const args = [
      poxAddressToTuple(account.btcAddr),
      Cl.uint(rewardCycle),
      Cl.uint(index),
      Cl.some(Cl.bufferFromHex(signerSignature)),
      signerKey,
      Cl.uint(maxAmount),
      Cl.uint(authId),
    ];
    response = simnet.callPublicFn(
      POX_CONTRACT,
      "stack-aggregation-increase",
      args,
      address2
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_INVALID_SIGNER_KEY));

    // check that the amount was not increased
    const info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-reward-set-pox-address",
      [Cl.uint(rewardCycle), Cl.uint(index)],
      address2
    );
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["total-ustx"]).toBeUint(amount);
  });
});

describe("test `delegate-stack-extend`", () => {
  it("returns `(ok <lockup-info>)` on success", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      6,
      address2
    );
    // unlock height should be cycle 8: 8 * 1050 = 8400
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(8400),
      })
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(7);
  });

  it("can extend after commit", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    const rewardCycle = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );
    stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      6,
      address2
    );
    // unlock height should be cycle 8: 8 * 1050 = 8400
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(8400),
      })
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(7);
  });

  it("can extend after lock has started", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    const rewardCycle = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );
    stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );

    simnet.mineEmptyBlocks(1100);

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      6,
      address2
    );
    // unlock height should be cycle 8: 8 * 1050 = 8400
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(8400),
      })
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(7);
  });

  it("can extend multiple times", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      2,
      address2
    );
    // unlock height should be cycle 4: 4 * 1050 = 4200
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(4200),
      })
    );

    response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      3,
      address2
    );
    // unlock height should be cycle 7: 7 * 1050 = 7350
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(7350),
      })
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(6);
  });

  it("can extend multiple times while locked", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    simnet.mineEmptyBlocks(1100);

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      2,
      address2
    );
    // unlock height should be cycle 4: 4 * 1050 = 4200
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(4200),
      })
    );

    simnet.mineEmptyBlocks(3000);

    response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      3,
      address2
    );
    // unlock height should be cycle 7: 7 * 1050 = 7350
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(7350),
      })
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(3);
    expect(tuple.data["lock-period"]).toBeUint(4);
  });

  it("cannot extend 0 cycles", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      0,
      address2
    );

    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_INVALID_LOCK_PERIOD)
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(1);
  });

  it("cannot extend beyond 12 cycles", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      12,
      address2
    );

    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_INVALID_LOCK_PERIOD)
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(1);
  });

  it("cannot be called indirectly by an unauthorized caller", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    const delegateStackExtendArgs = [
      Cl.principal(account.stxAddress),
      poxAddressToTuple(account.btcAddr),
      Cl.uint(6),
    ];
    let response = simnet.callPublicFn(
      "indirect",
      "delegate-stack-extend",
      delegateStackExtendArgs,
      address2
    );

    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(1);
  });

  it("can be called indirectly by an authorized caller", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    allowContractCaller(`${deployer}.indirect`, null, address2);
    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    const delegateStackExtendArgs = [
      Cl.principal(account.stxAddress),
      poxAddressToTuple(account.btcAddr),
      Cl.uint(6),
    ];
    let response = simnet.callPublicFn(
      "indirect",
      "delegate-stack-extend",
      delegateStackExtendArgs,
      address2
    );

    // unlock height should be cycle 8: 8 * 1050 = 84000
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(8400),
      })
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(7);
  });

  it("cannot extend if not locked", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      6,
      address2
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_STACK_EXTEND_NOT_LOCKED));

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalNone);
  });

  it("cannot extend after lock has expired", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    const rewardCycle = 1;
    const period = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      period,
      address2
    );
    stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );

    simnet.mineEmptyBlocks(2200);

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      6,
      address2
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_STACK_EXTEND_NOT_LOCKED));

    const info = getStackerInfo(account.stxAddress);
    expect(info.result).toBeNone();
  });

  it("cannot extend at unlock height", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    const rewardCycle = 1;
    const period = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      period,
      address2
    );
    stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );

    // mine until the unlock height
    simnet.mineEmptyBlocks(2100 - simnet.blockHeight);

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      6,
      address2
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_STACK_EXTEND_NOT_LOCKED));

    const info = getStackerInfo(account.stxAddress);
    expect(info.result).toBeNone();
  });

  it("cannot extend a solo-stacked stacker", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    const period = 1;
    const authId = 1;

    stackStx(
      account,
      amount,
      1000,
      period,
      maxAmount,
      authId,
      account.stxAddress
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      6,
      account.stxAddress
    );
    expect(response.result).toBeErr(Cl.int(ERRORS.ERR_STACKING_NOT_DELEGATED));

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(1);
  });

  it("cannot extend a stacker not delegated to the caller", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      6,
      address3
    );
    // unlock height should be cycle 8: 8 * 1050 = 8400
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(1);
  });

  it("cannot extend to a different pox addr", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      stackers[1].btcAddr,
      6,
      address2
    );
    // unlock height should be cycle 8: 8 * 1050 = 8400
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_DELEGATION_POX_ADDR_REQUIRED)
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(1);
  });

  it("can extend to a different pox addr if one was not specified", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, null, null, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      stackers[1].btcAddr,
      6,
      address2
    );
    // unlock height should be cycle 8: 8 * 1050 = 8400
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(8400),
      })
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(7);
  });

  it("can extend within the delegation window", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, 5250, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      3,
      address2
    );
    // unlock height should be cycle 5: 5 * 1050 = 5250
    expect(response.result).toBeOk(
      Cl.tuple({
        stacker: Cl.principal(account.stxAddress),
        "unlock-burn-height": Cl.uint(5250),
      })
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(4);
  });

  it("cannot extend outside the delegation window", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;

    delegateStx(maxAmount, address2, 5249, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let response = delegateStackExtend(
      account.stxAddress,
      account.btcAddr,
      3,
      address2
    );
    expect(response.result).toBeErr(
      Cl.int(ERRORS.ERR_DELEGATION_EXPIRES_DURING_LOCK)
    );

    const info = getStackerInfo(account.stxAddress);
    expect(info.result.type).toBe(ClarityType.OptionalSome);
    const tuple = (info.result as SomeCV).value as TupleCV;
    expect(tuple.data["first-reward-cycle"]).toBeUint(1);
    expect(tuple.data["lock-period"]).toBeUint(1);
  });
});

describe("test `get-partial-stacked-by-cycle`", () => {
  it("returns the correct amount", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    const rewardCycle = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    const info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-partial-stacked-by-cycle",
      [
        poxAddressToTuple(account.btcAddr),
        Cl.uint(rewardCycle),
        Cl.principal(address2),
      ],
      address2
    );
    expect(info.result).toBeSome(
      Cl.tuple({
        "stacked-amount": Cl.uint(amount),
      })
    );
  });

  it("returns `none` when there are no partially stacked STX", () => {
    const account = stackers[0];
    const rewardCycle = 1;

    const info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-partial-stacked-by-cycle",
      [
        poxAddressToTuple(account.btcAddr),
        Cl.uint(rewardCycle),
        Cl.principal(address2),
      ],
      address2
    );
    expect(info.result).toBeNone();
  });

  it("returns `none` after fully stacked", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    const rewardCycle = 1;
    const authId = 1;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      1,
      address2
    );

    let info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-partial-stacked-by-cycle",
      [
        poxAddressToTuple(account.btcAddr),
        Cl.uint(rewardCycle),
        Cl.principal(address2),
      ],
      address2
    );
    expect(info.result).toBeSome(
      Cl.tuple({
        "stacked-amount": Cl.uint(amount),
      })
    );

    stackAggregationCommitIndexed(
      account,
      rewardCycle,
      maxAmount,
      authId,
      address2
    );

    info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-partial-stacked-by-cycle",
      [
        poxAddressToTuple(account.btcAddr),
        Cl.uint(rewardCycle),
        Cl.principal(address2),
      ],
      address2
    );
    expect(info.result).toBeNone();
  });

  it("returns the correct amount for multiple cycles", () => {
    const account = stackers[0];
    const amount = getStackingMinimum() * 2n;
    const maxAmount = amount * 2n;
    const rewardCycle = 4;

    delegateStx(maxAmount, address2, null, account.btcAddr, account.stxAddress);
    delegateStackStx(
      account.stxAddress,
      amount,
      account.btcAddr,
      1000,
      6,
      address2
    );

    const info = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-partial-stacked-by-cycle",
      [
        poxAddressToTuple(account.btcAddr),
        Cl.uint(rewardCycle),
        Cl.principal(address2),
      ],
      address2
    );
    expect(info.result).toBeSome(
      Cl.tuple({
        "stacked-amount": Cl.uint(amount),
      })
    );
  });
});
