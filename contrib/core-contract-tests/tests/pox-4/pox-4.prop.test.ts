import {
  Cl,
  ClarityType,
  ClarityValue,
  createStacksPrivateKey,
  isClarityType,
  pubKeyfromPrivKey,
  serializeCV,
  signWithKey,
} from "@stacks/transactions";
import fc from "fast-check";
import { assert, describe, expect, it } from "vitest";
import { createHash } from "crypto";

// Contract Consts
const INITIAL_TOTAL_LIQ_SUPPLY = 1_000_000_000_000_000;
const MIN_AMOUNT_USTX = 125_000_000_000n;
const TESTNET_PREPARE_CYCLE_LENGTH = 50;
const TESTNET_REWARD_CYCLE_LENGTH = 1050;
const TESTNET_STACKING_THRESHOLD_25 = 8000;
// Clarity
const MAX_CLAR_UINT = 340282366920938463463374607431768211455n;
const TESTNET_CHAIN_ID = 2147483648;
const SIP_018_MESSAGE_PREFIX = "534950303138";
// Error Codes
const ERR_STACKING_INVALID_LOCK_PERIOD = 2;
const ERR_STACKING_THRESHOLD_NOT_MET = 11;
const ERR_STACKING_INVALID_POX_ADDRESS = 13;
const ERR_STACKING_INVALID_AMOUNT = 18;
const ERR_INVALID_SIGNATURE_PUBKEY = 35;
const ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH = 38;
// Private Keys
const privateKeyMapping: {
  [key: string]: string;
} = {
  ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM:
    "753b7cc01a1a2e86221266a154af739463fce51219d97e4f856cd7200c3bd2a601",
  ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5:
    "7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801",
  ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG:
    "530d9f61984c888536871c6573073bdfc0058896dc1adfe9a6a10dfacadc209101",
  ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC:
    "d655b2523bcd65e34889725c73064feb17ceb796831c0e111ba1a552b0f31b3901",
  ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND:
    "f9d7206a47f14d2870c163ebab4bf3e70d18f5d14ce1031f3902fbbc894fe4c701",
  ST2REHHS5J3CERCRBEPMGH7921Q6PYKAADT7JP2VB:
    "3eccc5dac8056590432db6a35d52b9896876a3d5cbdea53b72400bc9c2099fe801",
  ST3AM1A56AK2C1XAFJ4115ZSV26EB49BVQ10MGCS0:
    "7036b29cb5e235e5fd9b09ae3e8eec4404e44906814d5d01cbca968a60ed4bfb01",
  ST3PF13W7Z0RRM42A8VZRVFQ75SV1K26RXEP8YGKJ:
    "b463f0df6c05d2f156393eee73f8016c5372caa0e9e29a901bb7171d90dc4f1401",
  ST3NBRSFKX28FQ2ZJ1MAKX58HKHSDGNV5N7R21XCP:
    "6a1a754ba863d7bab14adbbc3f8ebb090af9e871ace621d3e5ab634e1422885e01",
  STNHKEPYEPJ8ET55ZZ0M5A34J0R3N5FM2CMMMAZ6:
    "de433bdfa14ec43aa1098d5be594c8ffb20a31485ff9de2923b2689471c401b801",
};

const sha256 = (data: Buffer): Buffer =>
  createHash("sha256").update(data).digest();

const structuredDataHash = (structuredData: ClarityValue): Buffer =>
  sha256(Buffer.from(serializeCV(structuredData)));

const generateDomainHash = (): ClarityValue =>
  Cl.tuple({
    name: Cl.stringAscii("pox-4-signer"),
    version: Cl.stringAscii("1.0.0"),
    "chain-id": Cl.uint(TESTNET_CHAIN_ID),
  });

const generateMessageHash = (
  version: number,
  hashbytes: number[],
  reward_cycle: number,
  topic: string,
  period: number,
  auth_id: number,
  max_amount: number
): ClarityValue =>
  Cl.tuple({
    "pox-addr": Cl.tuple({
      version: Cl.buffer(Uint8Array.from([version])),
      hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
    }),
    "reward-cycle": Cl.uint(reward_cycle),
    topic: Cl.stringAscii(topic),
    period: Cl.uint(period),
    "auth-id": Cl.uint(auth_id),
    "max-amount": Cl.uint(max_amount),
  });

const generateMessagePrefixBuffer = (prefix: string) =>
  Buffer.from(prefix, "hex");

const buildSignerKeyMessageHash = (
  version: number,
  hashbytes: number[],
  reward_cycle: number,
  topic: string,
  period: number,
  max_amount: number,
  auth_id: number
) => {
  const domain_hash = structuredDataHash(generateDomainHash());
  const message_hash = structuredDataHash(
    generateMessageHash(
      version,
      hashbytes,
      reward_cycle,
      topic,
      period,
      auth_id,
      max_amount
    )
  );
  const structuredDataPrefix = generateMessagePrefixBuffer(
    SIP_018_MESSAGE_PREFIX
  );

  const signer_key_message_hash = sha256(
    Buffer.concat([structuredDataPrefix, domain_hash, message_hash])
  );

  return signer_key_message_hash;
};

const signMessageHash = (privateKey: string, messageHash: Buffer) => {
  const data = signWithKey(
    createStacksPrivateKey(privateKey),
    messageHash.toString("hex")
  ).data;
  return Buffer.from(data.slice(2) + data.slice(0, 2), "hex");
};

describe("test pox-4 contract read only functions", () => {
  it("should return correct reward-cycle-to-burn-height", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat(),
        (account, reward_cycle) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            account
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const first_burn_block_height =
            pox_4_info.value.data["first-burnchain-block-height"];
          const reward_cycle_length =
            pox_4_info.value.data["reward-cycle-length"];
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "reward-cycle-to-burn-height",
            [Cl.uint(reward_cycle)],
            account
          );
          // Assert
          assert(isClarityType(actual, ClarityType.UInt));
          assert(isClarityType(first_burn_block_height, ClarityType.UInt));
          assert(isClarityType(reward_cycle_length, ClarityType.UInt));
          const expected =
            Number(first_burn_block_height.value) +
            Number(reward_cycle_length.value) * reward_cycle;
          expect(actual).toBeUint(expected);
        }
      )
    );
  });

  it("should return correct burn-height-to-reward-cycle", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat(),
        (account, burn_height) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            account
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const first_burn_block_height =
            pox_4_info.value.data["first-burnchain-block-height"];
          const reward_cycle_length =
            pox_4_info.value.data["reward-cycle-length"];
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "burn-height-to-reward-cycle",
            [Cl.uint(burn_height)],
            account
          );
          // Assert
          assert(isClarityType(actual, ClarityType.UInt));
          assert(isClarityType(first_burn_block_height, ClarityType.UInt));
          assert(isClarityType(reward_cycle_length, ClarityType.UInt));
          const expected = Math.floor(
            (burn_height - Number(first_burn_block_height.value)) /
              Number(reward_cycle_length.value)
          );
          expect(actual).toBeUint(expected);
        }
      )
    );
  });

  it("should return u0 current-pox-reward-cycle", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller) => {
          // Arrange
          let expected = 0;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "current-pox-reward-cycle",
            [],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.UInt));
          expect(actual).toBeUint(expected);
        }
      )
    );
  });

  it("should return none get-stacker-info", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.constantFrom(...simnet.getAccounts().values()),
        (stacker, caller) => {
          // Arrange
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-stacker-info",
            [Cl.principal(stacker)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.OptionalNone));
          expect(actual).toBeNone();
        }
      )
    );
  });

  it("should return true check-caller-allowed", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller) => {
          // Arrange
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "check-caller-allowed",
            [],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.BoolTrue));
          expect(actual).toBeBool(true);
        }
      )
    );
  });

  it("should return u0 get-reward-set-size", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat(),
        (caller, reward_cycle) => {
          // Arrange
          const expected = 0;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-reward-set-size",
            [Cl.uint(reward_cycle)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.UInt));
          expect(actual).toBeUint(expected);
        }
      )
    );
  });

  it("should return u0 get-total-ustx-stacked", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat(),
        (caller, reward_cycle) => {
          // Arrange
          const expected = 0;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-total-ustx-stacked",
            [Cl.uint(reward_cycle)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.UInt));
          expect(actual).toBeUint(expected);
        }
      )
    );
  });

  it("should return none get-reward-set-pox-address", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat(),
        fc.nat(),
        (caller, index, reward_cycle) => {
          // Arrange
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-reward-set-pox-address",
            [Cl.uint(index), Cl.uint(reward_cycle)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.OptionalNone));
          expect(actual).toBeNone();
        }
      )
    );
  });

  it("should return correct get-stacking-minimum", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const stx_liq_supply =
            pox_4_info.value.data["total-liquid-supply-ustx"];
          assert(isClarityType(stx_liq_supply, ClarityType.UInt));
          const expected = Math.floor(
            Number(stx_liq_supply.value) / TESTNET_STACKING_THRESHOLD_25
          );
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-stacking-minimum",
            [],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.UInt));
          expect(actual).toBeUint(expected);
        }
      )
    );
  });

  it("should return true check-pox-addr-version for version <= 6 ", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat({ max: 6 }),
        (caller, version) => {
          // Arrange
          const expected = true;
          // Act
          let { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "check-pox-addr-version",
            [Cl.buffer(Uint8Array.from([version]))],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.BoolTrue));
          expect(actual).toBeBool(expected);
        }
      )
    );
  });

  it("should return false check-pox-addr-version for version > 6", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 7, max: 255 }),
        (caller, version) => {
          // Arrange
          const expected = false;
          // Act
          let { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "check-pox-addr-version",
            [Cl.buffer(Uint8Array.from([version]))],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.BoolFalse));
          expect(actual).toBeBool(expected);
        }
      )
    );
  });

  it("should return true check-pox-lock-period for valid reward cycles number", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 1, max: 12 }),
        (caller, valid_reward_cycles) => {
          // Arrange
          const expected = true;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "check-pox-lock-period",
            [Cl.uint(valid_reward_cycles)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.BoolTrue));
          expect(actual).toBeBool(expected);
        }
      )
    );
  });

  it("should return false check-pox-lock-period for reward cycles number > 12", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 13 }),
        (caller, invalid_reward_cycles) => {
          // Arrange
          const expected = false;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "check-pox-lock-period",
            [Cl.uint(invalid_reward_cycles)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.BoolFalse));
          expect(actual).toBeBool(expected);
        }
      )
    );
  });

  it("should return false check-pox-lock-period for reward cycles number == 0", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller) => {
          // Arrange
          const invalid_reward_cycles = 0;
          const expected = false;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "check-pox-lock-period",
            [Cl.uint(invalid_reward_cycles)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.BoolFalse));
          expect(actual).toBeBool(expected);
        }
      )
    );
  });

  it("should return (ok true) can-stack-stx for versions 0-4 valid pox addresses, hashbytes, amount, cycles number", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 4 }),
        fc.array(fc.nat({ max: 255 }), {
          minLength: 20,
          maxLength: 20,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseOk = true;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseOk));
          assert(isClarityType(actual.value, ClarityType.BoolTrue));
          expect(actual).toBeOk(Cl.bool(expectedResponseOk));
        }
      )
    );
  });

  it("should return (ok true) can-stack-stx for versions 5/6 valid pox addresses, hashbytes, amount, cycles number", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 5, max: 6 }),
        fc.array(fc.nat({ max: 255 }), {
          minLength: 32,
          maxLength: 32,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseOk = true;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseOk));
          assert(isClarityType(actual.value, ClarityType.BoolTrue));
          expect(actual).toBeOk(Cl.bool(expectedResponseOk));
        }
      )
    );
  });

  it("should return (err 13) can-stack-stx for pox addresses having version > 6", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({
          min: 7,
          max: 255,
        }),
        fc.array(fc.nat({ max: 255 }), {
          maxLength: 32,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 13) can-stack-stx for versions 0-4 pox addresses having hasbytes longer than 20", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 4 }),
        fc.array(fc.nat({ max: 255 }), {
          minLength: 21,
          maxLength: 32,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 13) can-stack-stx for versions 0-4 pox addresses having hasbytes shorter than 20", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 4 }),
        fc.array(fc.nat({ max: 255 }), {
          maxLength: 19,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 13) can-stack-stx for versions 5/6 pox addresses having hashbytes shorter than 32", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 4 }),
        fc.array(fc.nat({ max: 255 }), {
          maxLength: 31,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 11) can-stack-stx for unmet stacking threshold", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 6 }),
        fc.array(fc.nat({ max: 255 })),
        fc.bigInt({
          min: 0n,
          max: 124_999_999_999n,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_THRESHOLD_NOT_MET;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 2) can-stack-stx for lock period > 12", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 6 }),
        fc.array(fc.nat({ max: 255 })),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 13 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_LOCK_PERIOD;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (ok true) minimal-can-stack-stx for versions 0-4 valid pox addresses, hashbytes, amount, cycles number", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 4 }),
        fc.array(fc.nat({ max: 255 }), {
          minLength: 20,
          maxLength: 20,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseOk = true;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseOk));
          assert(isClarityType(actual.value, ClarityType.BoolTrue));
          expect(actual).toBeOk(Cl.bool(expectedResponseOk));
        }
      )
    );
  });

  it("should return (ok true) minimal-can-stack-stx for versions 5/6 valid pox addresses, hashbytes, amount, cycles number", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 5, max: 6 }),
        fc.array(fc.nat({ max: 255 }), {
          minLength: 32,
          maxLength: 32,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseOk = true;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseOk));
          assert(isClarityType(actual.value, ClarityType.BoolTrue));
          expect(actual).toBeOk(Cl.bool(expectedResponseOk));
        }
      )
    );
  });

  it("should return (err 13) minimal-can-stack-stx for pox addresses having version > 6", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({
          min: 7,
          max: 255,
        }),
        fc.array(fc.nat({ max: 255 }), {
          maxLength: 32,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 13) minimal-can-stack-stx for versions 0-4 pox addresses having hasbytes longer than 20", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 4 }),
        fc.array(fc.nat({ max: 255 }), {
          minLength: 21,
          maxLength: 32,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 13) minimal-can-stack-stx for versions 0-4 pox addresses having hasbytes shorter than 20", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 4 }),
        fc.array(fc.nat({ max: 255 }), {
          maxLength: 19,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 13) minimal-can-stack-stx for versions 5/6 pox addresses having hashbytes shorter than 32", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 4 }),
        fc.array(fc.nat({ max: 255 }), {
          maxLength: 31,
        }),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 2) minimal-can-stack-stx for lock period > 12", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 6 }),
        fc.array(fc.nat({ max: 255 })),
        fc.bigInt({
          min: MIN_AMOUNT_USTX,
          max: MAX_CLAR_UINT,
        }),
        fc.nat(),
        fc.integer({ min: 13 }),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_LOCK_PERIOD;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return (err 18) minimal-can-stack-stx for amount == 0", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.integer({ min: 0, max: 6 }),
        fc.array(fc.nat({ max: 255 }), { maxLength: 32 }),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (caller, version, hashbytes, first_rew_cycle, num_cycles) => {
          // Arrange
          const amount_ustx = 0;
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
          const expectedResponseErr = ERR_STACKING_INVALID_AMOUNT;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(amount_ustx),
              Cl.uint(first_rew_cycle),
              Cl.uint(num_cycles),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
        }
      )
    );
  });

  it("should return none get-check-delegation", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller) => {
          // Arrange
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-check-delegation",
            [Cl.principal(caller)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.OptionalNone));
        }
      )
    );
  });

  it("should return none get-delegation-info", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller) => {
          // Arrange
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-delegation-info",
            [Cl.principal(caller)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.OptionalNone));
        }
      )
    );
  });

  it("should return correct get-pox-info", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller) => {
          // Arrange
          const expected_reward_cycle_id = 0,
            expected_first_burn_block_height = 0;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-pox-info",
            [],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseOk));
          assert(isClarityType(actual.value, ClarityType.Tuple));
          expect(actual.value.data["first-burnchain-block-height"]).toBeUint(
            expected_first_burn_block_height
          );
          expect(actual.value.data["min-amount-ustx"]).toBeUint(
            MIN_AMOUNT_USTX
          );
          expect(actual.value.data["prepare-cycle-length"]).toBeUint(
            TESTNET_PREPARE_CYCLE_LENGTH
          );
          expect(actual.value.data["reward-cycle-id"]).toBeUint(
            expected_reward_cycle_id
          );
          expect(actual.value.data["reward-cycle-length"]).toBeUint(
            TESTNET_REWARD_CYCLE_LENGTH
          );
          expect(actual.value.data["total-liquid-supply-ustx"]).toBeUint(
            INITIAL_TOTAL_LIQ_SUPPLY
          );
        }
      )
    );
  });

  it("should return none get-allowance-contract-caller", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller, sender, contract_caller) => {
          // Arrange
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-allowance-contract-callers",
            [Cl.principal(sender), Cl.principal(contract_caller)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.OptionalNone));
        }
      )
    );
  });

  it("should return some(until-burn-ht: none) get-allowance-contract-caller after allow-contract-caller", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller, sender, contract_caller) => {
          // Arrange
          const { result: allow } = simnet.callPublicFn(
            "pox-4",
            "allow-contract-caller",
            [Cl.principal(contract_caller), Cl.none()],
            sender
          );
          assert(isClarityType(allow, ClarityType.ResponseOk));
          assert(isClarityType(allow.value, ClarityType.BoolTrue));
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-allowance-contract-callers",
            [Cl.principal(sender), Cl.principal(contract_caller)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.OptionalSome));
          assert(isClarityType(actual.value, ClarityType.Tuple));
          expect(actual).toBeSome(Cl.tuple({ "until-burn-ht": Cl.none() }));
        }
      )
    );
  });

  it("should return u0 get-num-reward-set-pox-addresses", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat(),
        (caller, reward_cycle) => {
          // Arrange
          const expected = 0;
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-num-reward-set-pox-addresses",
            [Cl.uint(reward_cycle)],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.UInt));
          expect(actual).toBeUint(expected);
        }
      )
    );
  });

  it("should return none get-partial-stacked-by-cycle", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat({ max: 6 }),
        fc.array(fc.nat({ max: 255 }), { maxLength: 32 }),
        fc.nat(),
        fc.constantFrom(...simnet.getAccounts().values()),
        (caller, version, hashbytes, reward_cycle, sender) => {
          // Arrange
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-partial-stacked-by-cycle",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(reward_cycle),
              Cl.principal(sender),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.OptionalNone));
        }
      )
    );
  });

  it("should return correct hash get-signer-key-message-hash", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat({ max: 6 }),
        fc.array(fc.nat({ max: 255 }), { maxLength: 32 }),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        (
          caller,
          version,
          hashbytes,
          reward_cycle,
          period,
          max_amount,
          auth_id
        ) => {
          // Arrange

          const signer_key_message_hash = buildSignerKeyMessageHash(
            version,
            hashbytes,
            reward_cycle,
            "topic",
            period,
            max_amount,
            auth_id
          );
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "get-signer-key-message-hash",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(reward_cycle),
              Cl.stringAscii("topic"),
              Cl.uint(period),
              Cl.uint(max_amount),
              Cl.uint(auth_id),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.Buffer));
          expect(actual).toBeBuff(signer_key_message_hash);
        }
      )
    );
  });

  it("should return (ok true) verify-signer-key-sig called with correct data", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat({ max: 6 }),
        fc.array(fc.nat({ max: 255 }), { maxLength: 32 }),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        (
          caller,
          version,
          hashbytes,
          reward_cycle,
          period,
          amount,
          max_amount,
          auth_id
        ) => {
          // Arrange
          fc.pre(amount <= max_amount);
          const signer_private_key = privateKeyMapping[caller] ?? "";
          const signer_key_message_hash = buildSignerKeyMessageHash(
            version,
            hashbytes,
            reward_cycle,
            "topic",
            period,
            max_amount,
            auth_id
          );
          const signer_sig = signMessageHash(
            signer_private_key,
            signer_key_message_hash
          );
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "verify-signer-key-sig",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(reward_cycle),
              Cl.stringAscii("topic"),
              Cl.uint(period),
              Cl.some(Cl.buffer(signer_sig)),
              Cl.buffer(pubKeyfromPrivKey(signer_private_key).data),
              Cl.uint(amount),
              Cl.uint(max_amount),
              Cl.uint(auth_id),
            ],
            caller
          );
          assert(isClarityType(actual, ClarityType.ResponseOk));
          assert(isClarityType(actual.value, ClarityType.BoolTrue));
          expect(actual).toBeOk(Cl.bool(true));
          expect(actual.value).toBeBool(true);
        }
      )
    );
  });

  it("should return (err 35) verify-signer-key-sig called with wrong public key", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat({ max: 6 }),
        fc.array(fc.nat({ max: 255 }), { maxLength: 32 }),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        fc.constantFrom(...simnet.getAccounts().values()),
        (
          caller,
          version,
          hashbytes,
          reward_cycle,
          period,
          amount,
          max_amount,
          auth_id,
          wrong_address
        ) => {
          // Arrange
          fc.pre(amount <= max_amount);
          fc.pre(wrong_address !== caller);
          const expectedResponseErr = ERR_INVALID_SIGNATURE_PUBKEY;
          const signer_private_key = privateKeyMapping[caller];
          const wrong_private_key = privateKeyMapping[wrong_address];
          const signer_key_message_hash = buildSignerKeyMessageHash(
            version,
            hashbytes,
            reward_cycle,
            "topic",
            period,
            max_amount,
            auth_id
          );
          const signer_sig = signMessageHash(
            signer_private_key,
            signer_key_message_hash
          );
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "verify-signer-key-sig",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(reward_cycle),
              Cl.stringAscii("topic"),
              Cl.uint(period),
              Cl.some(Cl.buffer(signer_sig)),
              Cl.buffer(pubKeyfromPrivKey(wrong_private_key).data),
              Cl.uint(amount),
              Cl.uint(max_amount),
              Cl.uint(auth_id),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
          expect(actual.value).toBeInt(expectedResponseErr);
        }
      )
    );
  });

  it("should return (err 38) verify-signer-key-sig called with wrong public key", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat({ max: 6 }),
        fc.array(fc.nat({ max: 255 }), { maxLength: 32 }),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        fc.nat(),
        (
          caller,
          version,
          hashbytes,
          reward_cycle,
          period,
          amount,
          max_amount,
          auth_id
        ) => {
          // Arrange
          fc.pre(amount > max_amount);
          const expectedResponseErr = ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH;
          const signer_private_key = privateKeyMapping[caller];
          const signer_key_message_hash = buildSignerKeyMessageHash(
            version,
            hashbytes,
            reward_cycle,
            "topic",
            period,
            max_amount,
            auth_id
          );
          const signer_sig = signMessageHash(
            signer_private_key,
            signer_key_message_hash
          );
          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            "pox-4",
            "verify-signer-key-sig",
            [
              Cl.tuple({
                version: Cl.buffer(Uint8Array.from([version])),
                hashbytes: Cl.buffer(Uint8Array.from(hashbytes)),
              }),
              Cl.uint(reward_cycle),
              Cl.stringAscii("topic"),
              Cl.uint(period),
              Cl.some(Cl.buffer(signer_sig)),
              Cl.buffer(pubKeyfromPrivKey(signer_private_key).data),
              Cl.uint(amount),
              Cl.uint(max_amount),
              Cl.uint(auth_id),
            ],
            caller
          );
          // Assert
          assert(isClarityType(actual, ClarityType.ResponseErr));
          assert(isClarityType(actual.value, ClarityType.Int));
          expect(actual).toBeErr(Cl.int(expectedResponseErr));
          expect(actual.value).toBeInt(expectedResponseErr);
        }
      )
    );
  });
});
