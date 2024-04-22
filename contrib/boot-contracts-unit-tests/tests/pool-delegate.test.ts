import { assert, beforeEach, describe, expect, it } from "vitest";

import { Cl } from "@stacks/transactions";
import { Pox4SignatureTopic, poxAddressToTuple } from "@stacks/stacking";
import {
  ERRORS,
  POX_CONTRACT,
  allowContractCaller,
  delegateStackStx,
  delegateStx,
  getStackingMinimum,
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

  it("returns an error when not called by an authorized caller", () => {
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

  it("returns an error when not called by an authorized caller", () => {
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
