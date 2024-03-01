import Cl, { ClarityType, bufferCV, isClarityType } from "@stacks/transactions";
import { assert, describe, expect, it } from "vitest";
import fc from "fast-check";

const POX_4 = "pox-4";
const GET_POX_INFO = "get-pox-info";

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
            [Cl.uintCV(reward_cycle)],
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
      ),
      { numRuns: 300 }
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
            [Cl.uintCV(burn_height)],
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
      ),
      { numRuns: 300 }
    );
  });

  it("should return none stacker-info", () => {
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
            [Cl.principalCV(stacker)],
            caller
          );

          // Assert
          assert(isClarityType(actual, ClarityType.OptionalNone));
          expect(actual).toBeNone();
        }
      )
    );
  });

  it("should return correct check-caller-allowed", () => {
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
            [Cl.uintCV(reward_cycle)],
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
            [Cl.uintCV(reward_cycle)],
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
            [Cl.uintCV(index), Cl.uintCV(reward_cycle)],
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
          const testnet_stacking_threshold_25 = 8000;

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
            Number(stx_liq_supply.value) / testnet_stacking_threshold_25
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

  it("should return correct check-pox-addr-version", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat({ max: 255 }),
        (caller, version) => {
          // Arrange
          const expected = version > 6 ? false : true;

          // Act
          let { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "check-pox-addr-version",
            [Cl.bufferCV(Uint8Array.from([version]))],
            caller
          );

          // Assert
          assert(
            isClarityType(
              actual,
              expected ? ClarityType.BoolTrue : ClarityType.BoolFalse
            )
          );
          expect(actual).toBeBool(expected);
        }
      )
    );
  });

  it("should return correct check-pox-lock-period", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat(),
        (caller, reward_cycles) => {
          // Arrange
          const expected =
            reward_cycles > 0 && reward_cycles <= 12 ? true : false;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "check-pox-lock-period",
            [Cl.uintCV(reward_cycles)],
            caller
          );

          // Assert
          assert(
            isClarityType(
              actual,
              expected ? ClarityType.BoolTrue : ClarityType.BoolFalse
            )
          );
          expect(actual).toBeBool(expected);
        }
      )
    ),
      { numRuns: 250 };
  });

  it("should return correct can-stack-stx", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...simnet.getAccounts().values()),
        fc.nat({ max: 255 }),
        fc.array(fc.nat({ max: 255 }), { maxLength: 32 }),
        fc.bigInt({ min: 0n, max: 340282366920938463463374607431768211455n }),
        fc.nat(),
        fc.nat(),
        (
          caller,
          version,
          hashbytes,
          amount_ustx,
          first_rew_cycle,
          num_cycles
        ) => {
          // Arrange
          const testnet_stacking_threshold_25 = 8000;

          const { result: pox_4_info } = simnet.callReadOnlyFn(
            POX_4,
            GET_POX_INFO,
            [],
            caller
          );
          assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
          assert(isClarityType(pox_4_info.value, ClarityType.Tuple));

          const stacking_valid_amount = amount_ustx > 0;
          const pox_lock_period_valid = num_cycles > 0 && num_cycles <= 12;
          const pox_version_valid = version <= 6;
          const pox_hashbytes_valid =
            hashbytes.length === 20 || hashbytes.length === 32;
          const stx_liq_supply =
            pox_4_info.value.data["total-liquid-supply-ustx"];

          assert(isClarityType(stx_liq_supply, ClarityType.UInt));
          const stacking_threshold_met =
            amount_ustx >=
            Math.floor(
              Number(stx_liq_supply.value) / testnet_stacking_threshold_25
            );
          const expectedResponseErr = !stacking_threshold_met
            ? 11
            : !stacking_valid_amount
            ? 18
            : !pox_lock_period_valid
            ? 2
            : !pox_version_valid
            ? 13
            : !pox_hashbytes_valid
            ? 13
            : 0;
          const expectedResponseOk = true;

          // Act
          const { result: actual } = simnet.callReadOnlyFn(
            POX_4,
            "can-stack-stx",
            [
              Cl.tupleCV({
                version: bufferCV(Uint8Array.from([version])),
                hashbytes: bufferCV(Uint8Array.from(hashbytes)),
              }),
              Cl.uintCV(amount_ustx),
              Cl.uintCV(first_rew_cycle),
              Cl.uintCV(num_cycles),
            ],
            caller
          );

          // Assert
          assert(
            isClarityType(
              actual,
              stacking_threshold_met &&
                stacking_valid_amount &&
                pox_lock_period_valid &&
                pox_version_valid &&
                pox_hashbytes_valid
                ? ClarityType.ResponseOk
                : ClarityType.ResponseErr
            )
          );

          assert(
            isClarityType(
              actual.value,
              stacking_threshold_met &&
                stacking_valid_amount &&
                pox_lock_period_valid &&
                pox_version_valid &&
                pox_hashbytes_valid
                ? ClarityType.BoolTrue
                : ClarityType.Int
            )
          );
          if (expectedResponseErr === 0) {
            expect(actual).toBeOk(
              Cl.responseOkCV(Cl.boolCV(expectedResponseOk))
            );
            expect(actual.value).toBeBool(expectedResponseOk);
          } else {
            expect(actual).toBeErr(Cl.intCV(expectedResponseErr));
            expect(actual.value).toBeInt(expectedResponseErr);
          }
        }
      ),
      { numRuns: 300 }
    );
  });
});
