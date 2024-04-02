import crypto from "node:crypto";
import {
  Cl,
  ClarityType,
  getAddressFromPrivateKey,
  TransactionVersion,
  createStacksPrivateKey,
  isClarityType,
  StacksPrivateKey,
  UIntCV,
  cvToString,
} from "@stacks/transactions";
import { describe, expect, it, beforeEach, assert } from "vitest";
import { StacksDevnet } from "@stacks/network";
import {
  getPublicKeyFromPrivate,
  publicKeyToBtcAddress,
} from "@stacks/encryption";
import {
  Pox4SignatureTopic,
  StackingClient,
  poxAddressToTuple,
} from "@stacks/stacking";
import { Simnet } from "@hirosystems/clarinet-sdk";

const accounts = simnet.getAccounts();
const address1 = accounts.get("wallet_1")!;

const POX_DEPLOYER = "ST000000000000000000002AMW42H";
const POX_CONTRACT = `${POX_DEPLOYER}.pox-4`;

// Error codes from the contract
const ERR_STACKING_UNREACHABLE = 255;
const ERR_STACKING_CORRUPTED_STATE = 254;
const ERR_STACKING_INSUFFICIENT_FUNDS = 1;
const ERR_STACKING_INVALID_LOCK_PERIOD = 2;
const ERR_STACKING_ALREADY_STACKED = 3;
const ERR_STACKING_NO_SUCH_PRINCIPAL = 4;
const ERR_STACKING_EXPIRED = 5;
const ERR_STACKING_STX_LOCKED = 6;
const ERR_STACKING_PERMISSION_DENIED = 9;
const ERR_STACKING_THRESHOLD_NOT_MET = 11;
const ERR_STACKING_POX_ADDRESS_IN_USE = 12;
const ERR_STACKING_INVALID_POX_ADDRESS = 13;
const ERR_STACKING_INVALID_AMOUNT = 18;
const ERR_NOT_ALLOWED = 19;
const ERR_STACKING_ALREADY_DELEGATED = 20;
const ERR_DELEGATION_EXPIRES_DURING_LOCK = 21;
const ERR_DELEGATION_TOO_MUCH_LOCKED = 22;
const ERR_DELEGATION_POX_ADDR_REQUIRED = 23;
const ERR_INVALID_START_BURN_HEIGHT = 24;
const ERR_NOT_CURRENT_STACKER = 25;
const ERR_STACK_EXTEND_NOT_LOCKED = 26;
const ERR_STACK_INCREASE_NOT_LOCKED = 27;
const ERR_DELEGATION_NO_REWARD_SLOT = 28;
const ERR_DELEGATION_WRONG_REWARD_SLOT = 29;
const ERR_STACKING_IS_DELEGATED = 30;
const ERR_STACKING_NOT_DELEGATED = 31;
const ERR_INVALID_SIGNER_KEY = 32;
const ERR_REUSED_SIGNER_KEY = 33;
const ERR_DELEGATION_ALREADY_REVOKED = 34;
const ERR_INVALID_SIGNATURE_PUBKEY = 35;
const ERR_INVALID_SIGNATURE_RECOVER = 36;
const ERR_INVALID_REWARD_CYCLE = 37;
const ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH = 38;
const ERR_SIGNER_AUTH_USED = 39;
const ERR_INVALID_INCREASE = 40;

// Keys to use for stacking
// wallet_1, wallet_2, wallet_3 private keys
const stackingKeys = [
  "7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801",
  "530d9f61984c888536871c6573073bdfc0058896dc1adfe9a6a10dfacadc209101",
  "d655b2523bcd65e34889725c73064feb17ceb796831c0e111ba1a552b0f31b3901",
];

type StackerInfo = {
  authId: number;
  privKey: string;
  pubKey: string;
  stxAddress: string;
  btcAddr: string;
  signerPrivKey: StacksPrivateKey;
  signerPubKey: string;
  client: StackingClient;
};

const stackers: StackerInfo[] = stackingKeys.map((privKey, i) => {
  const network = new StacksDevnet();

  const pubKey = getPublicKeyFromPrivate(privKey);
  const stxAddress = getAddressFromPrivateKey(
    privKey,
    TransactionVersion.Testnet
  );
  const signerPrivKey = createStacksPrivateKey(privKey);
  const signerPubKey = getPublicKeyFromPrivate(signerPrivKey.data);

  return {
    authId: i,
    privKey,
    pubKey,
    stxAddress,
    btcAddr: publicKeyToBtcAddress(pubKey),
    signerPrivKey: signerPrivKey,
    signerPubKey: signerPubKey,
    client: new StackingClient(stxAddress, network),
  };
});

const getPoxInfo = (simnet: Simnet, poxContract: string) => {
  const poxInfo = simnet.callReadOnlyFn(
    poxContract,
    "get-pox-info",
    [],
    address1
  );
  // @ts-ignore
  const data = poxInfo.result.value.data;
  const typedPoxInfo = {
    firstBurnchainBlockHeight: data["first-burnchain-block-height"]
      .value as bigint,
    minAmountUstx: data["min-amount-ustx"].value as bigint,
    prepareCycleLength: data["prepare-cycle-length"].value as bigint,
    rewardCycleId: data["reward-cycle-id"].value as bigint,
    rewardCycleLength: data["reward-cycle-length"].value as bigint,
    totalLiquidSupplyUstx: data["total-liquid-supply-ustx"].value as bigint,
  };

  return typedPoxInfo;
};

const getStackingMinimum = (simnet: Simnet, poxContract: string) => {
  const response = simnet.callReadOnlyFn(
    poxContract,
    "get-stacking-minimum",
    [],
    address1
  );
  return Number((response.result as UIntCV).value);
};

const burnHeightToRewardCycle = (burnHeight: number) => {
  const poxInfo = getPoxInfo(simnet, POX_CONTRACT);
  return Number(
    (BigInt(burnHeight) - poxInfo.firstBurnchainBlockHeight) /
      poxInfo.rewardCycleLength
  );
};

// Helper function to create a new stacking transaction
const stackStx = (
  stacker: StackerInfo,
  amount: number,
  startBurnHeight: number,
  lockPeriod: number,
  maxAmount: number,
  authId: number
) => {
  const rewardCycle = burnHeightToRewardCycle(startBurnHeight);
  const sigArgs = {
    authId,
    maxAmount,
    rewardCycle,
    period: lockPeriod,
    topic: Pox4SignatureTopic.StackStx,
    poxAddress: stacker.btcAddr,
    signerPrivateKey: stacker.signerPrivKey,
  };
  const signerSignature = stacker.client.signPoxSignature(sigArgs);
  const signerKey = Cl.bufferFromHex(stacker.signerPubKey);

  const stackStxArgs = [
    Cl.uint(amount),
    poxAddressToTuple(stacker.btcAddr),
    Cl.uint(startBurnHeight),
    Cl.uint(lockPeriod),
    Cl.some(Cl.bufferFromHex(signerSignature)),
    signerKey,
    Cl.uint(maxAmount),
    Cl.uint(authId),
  ];

  return simnet.callPublicFn(POX_CONTRACT, "stack-stx", stackStxArgs, address1);
};

describe("test `set-burnchain-parameters`", () => {
  it("sets the parameters correctly", () => {
    const response = simnet.callPublicFn(
      POX_CONTRACT,
      "set-burnchain-parameters",
      [Cl.uint(100), Cl.uint(5), Cl.uint(20), Cl.uint(6)],
      address1
    );
    expect(response.result).toBeOk(Cl.bool(true));

    const fbbh = simnet.getDataVar(
      POX_CONTRACT,
      "first-burnchain-block-height"
    );
    expect(fbbh).toBeUint(100);

    const ppcl = simnet.getDataVar(POX_CONTRACT, "pox-prepare-cycle-length");
    expect(ppcl).toBeUint(5);

    const prcl = simnet.getDataVar(POX_CONTRACT, "pox-reward-cycle-length");
    expect(prcl).toBeUint(20);

    const configured = simnet.getDataVar(POX_CONTRACT, "configured");
    expect(configured).toBeBool(true);
  });

  it("cannot be called twice", () => {
    simnet.callPublicFn(
      POX_CONTRACT,
      "set-burnchain-parameters",
      [Cl.uint(100), Cl.uint(5), Cl.uint(20), Cl.uint(6)],
      address1
    );
    const response = simnet.callPublicFn(
      POX_CONTRACT,
      "set-burnchain-parameters",
      [Cl.uint(101), Cl.uint(6), Cl.uint(21), Cl.uint(7)],
      address1
    );
    expect(response.result).toBeErr(Cl.int(ERR_NOT_ALLOWED));
  });
});

describe("test `burn-height-to-reward-cycle`", () => {
  it("returns the correct reward cycle", () => {
    let response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(1)],
      address1
    );
    expect(response.result).toBeUint(0);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(2099)],
      address1
    );
    expect(response.result).toBeUint(1);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(2100)],
      address1
    );
    expect(response.result).toBeUint(2);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(2101)],
      address1
    );
    expect(response.result).toBeUint(2);
  });

  it("returns the correct reward cycle with modified configuration", () => {
    simnet.callPublicFn(
      POX_CONTRACT,
      "set-burnchain-parameters",
      [Cl.uint(100), Cl.uint(5), Cl.uint(20), Cl.uint(6)],
      address1
    );

    expect(() =>
      simnet.callReadOnlyFn(
        POX_CONTRACT,
        "burn-height-to-reward-cycle",
        [Cl.uint(1)],
        address1
      )
    ).toThrowError();

    expect(() =>
      simnet.callReadOnlyFn(
        POX_CONTRACT,
        "burn-height-to-reward-cycle",
        [Cl.uint(99)],
        address1
      )
    ).toThrowError();

    let response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(100)],
      address1
    );
    expect(response.result).toBeUint(0);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(101)],
      address1
    );
    expect(response.result).toBeUint(0);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(119)],
      address1
    );
    expect(response.result).toBeUint(0);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(120)],
      address1
    );
    expect(response.result).toBeUint(1);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(121)],
      address1
    );
    expect(response.result).toBeUint(1);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "burn-height-to-reward-cycle",
      [Cl.uint(140)],
      address1
    );
    expect(response.result).toBeUint(2);
  });
});

describe("test `reward-cycle-to-burn-height`", () => {
  it("returns the correct burn height", () => {
    let response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "reward-cycle-to-burn-height",
      [Cl.uint(0)],
      address1
    );
    expect(response.result).toBeUint(0);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "reward-cycle-to-burn-height",
      [Cl.uint(1)],
      address1
    );
    expect(response.result).toBeUint(1050);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "reward-cycle-to-burn-height",
      [Cl.uint(2)],
      address1
    );
    expect(response.result).toBeUint(2100);

    expect(() =>
      simnet.callReadOnlyFn(
        POX_CONTRACT,
        "reward-cycle-to-burn-height",
        [Cl.uint(340282366920938463463374607431768211455n)],
        address1
      )
    ).toThrowError();
  });
});

describe("test `current-pox-reward-cycle`", () => {
  it("returns the correct reward cycle", () => {
    let response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "current-pox-reward-cycle",
      [],
      address1
    );
    expect(response.result).toBeUint(0);

    simnet.mineEmptyBlocks(2099);

    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "current-pox-reward-cycle",
      [],
      address1
    );
    expect(response.result).toBeUint(1);

    simnet.mineEmptyBlock();
    response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "current-pox-reward-cycle",
      [],
      address1
    );
    expect(response.result).toBeUint(2);
  });
});

describe("test `get-stacker-info`", () => {
  it("returns none when principal is not stacked", () => {
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-stacker-info",
      [Cl.principal(address1)],
      address1
    );
    expect(response.result).toBeNone();
  });

  it("returns info before stacked", () => {
    const stacker = stackers[0];
    const amount = getStackingMinimum(simnet, POX_CONTRACT) * 1.2;
    let stackResponse = stackStx(
      stacker,
      amount,
      1000,
      6,
      amount,
      stacker.authId
    );
    expect(stackResponse.result.type).toBe(ClarityType.ResponseOk);
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-stacker-info",
      [Cl.principal(stacker.stxAddress)],
      address1
    );
    expect(response.result).toBeSome(
      Cl.tuple({
        "delegated-to": Cl.none(),
        "first-reward-cycle": Cl.uint(1),
        "lock-period": Cl.uint(6),
        "pox-addr": poxAddressToTuple(stacker.btcAddr),
        "reward-set-indexes": Cl.list([
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(0),
        ]),
      })
    );
  });

  it("returns info while stacked", () => {
    const stacker = stackers[0];
    const amount = getStackingMinimum(simnet, POX_CONTRACT) * 1.2;
    let stackResponse = stackStx(
      stacker,
      amount,
      1000,
      6,
      amount,
      stacker.authId
    );
    expect(stackResponse.result.type).toBe(ClarityType.ResponseOk);
    simnet.mineEmptyBlocks(2100);
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-stacker-info",
      [Cl.principal(stacker.stxAddress)],
      address1
    );
    expect(response.result).toBeSome(
      Cl.tuple({
        "delegated-to": Cl.none(),
        "first-reward-cycle": Cl.uint(1),
        "lock-period": Cl.uint(6),
        "pox-addr": poxAddressToTuple(stacker.btcAddr),
        "reward-set-indexes": Cl.list([
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(0),
          Cl.uint(0),
        ]),
      })
    );
  });

  it("returns none after stacking expired", () => {
    const stacker = stackers[0];
    const amount = getStackingMinimum(simnet, POX_CONTRACT) * 1.2;
    let stackResponse = stackStx(
      stacker,
      amount,
      1000,
      6,
      amount,
      stacker.authId
    );
    expect(stackResponse.result.type).toBe(ClarityType.ResponseOk);
    simnet.mineEmptyBlocks(7350);
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-stacker-info",
      [Cl.principal(stacker.stxAddress)],
      address1
    );
    expect(response.result).toBeNone();
  });
});

describe("test 'check-caller-allowed'", () => {
  it ("returns true when called directly", () => {
    const response = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "check-caller-allowed",
      [],
      address1
    );
    expect(response.result).toBeBool(true);
  });
});
