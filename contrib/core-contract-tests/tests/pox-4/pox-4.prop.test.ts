import {
  Cl,
  ClarityType,
  bufferCV,
  cvToJSON,
  isClarityType,
} from "@stacks/transactions";
import { assert, describe, expect, it } from "vitest";
import fc from "fast-check";

// contracts
const POX_4 = "pox-4";
// methods
const GET_POX_INFO = "get-pox-info";
// contract consts
const TESTNET_STACKING_THRESHOLD_25 = 8000;
// error codes
const ERR_STACKING_INVALID_LOCK_PERIOD = 2;
const ERR_STACKING_THRESHOLD_NOT_MET = 11;
const ERR_STACKING_INVALID_POX_ADDRESS = 13;
const ERR_STACKING_INVALID_AMOUNT = 18;

fc.configureGlobal({ numRuns: 250 });

describe("test pox-4 contract read only functions", () => {
  it("should return correct reward-cycle-to-burn-height", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat(),
        (account, reward_cycle) => {
          // Arrange
          const { result: pox_4_info } = simnet.callReadOnlyFn(
            POX_4,
            GET_POX_INFO,
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
            POX_4,
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
            POX_4,
            GET_POX_INFO,
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
            POX_4,
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

  it("should return none get-stacker-info", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.constantFrom(...simnet.getAccounts().values()),
        (stacker, caller) => {
          // Arrange

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
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
            POX_4,
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
            POX_4,
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
            POX_4,
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
            POX_4,
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
            POX_4,
            GET_POX_INFO,
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
            POX_4,
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
            POX_4,
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
            POX_4,
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
        (caller, reward_cycles) => {
          // Arrange
          const expected = true;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "check-pox-lock-period",
            [Cl.uint(reward_cycles)],
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
        (caller, reward_cycles) => {
          // Arrange
          const expected = false;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "check-pox-lock-period",
            [Cl.uint(reward_cycles)],
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
          const reward_cycles = 0;
          const expected = false;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "check-pox-lock-period",
            [Cl.uint(reward_cycles)],
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseOk = true;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseOk = true;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          minLength: 32,
          maxLength: 32,
        }),
        fc.bigInt({
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_THRESHOLD_NOT_MET;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_LOCK_PERIOD;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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

  // minimal can stack stx
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseOk = true;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseOk = true;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          minLength: 32,
          maxLength: 32,
        }),
        fc.bigInt({
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_POX_ADDRESS;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
          min: 125_000_000_000n,
          max: 340282366920938463463374607431768211455n,
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
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_LOCK_PERIOD;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
        fc.integer(),
        fc.array(fc.nat({ max: 255 })),
        fc.nat(),
        fc.integer({ min: 1, max: 12 }),
        (caller, version, hashbytes, first_rew_cycle, num_cycles) => {
          // Arrange
          const amount_ustx = 0;

          const { result: pox_4_info } = simnet.callReadOnlyFn(
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const expectedResponseErr = ERR_STACKING_INVALID_AMOUNT;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "minimal-can-stack-stx",
            [
              Cl.tuple({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
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
});
