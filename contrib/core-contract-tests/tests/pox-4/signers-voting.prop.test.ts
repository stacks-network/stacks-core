import fc from "fast-check";
import { assert, expect, it } from "vitest";
import { Cl, ClarityType, isClarityType } from "@stacks/transactions";

it("should return correct reward-cycle-to-burn-height", () => {
  fc.assert(
    fc.property(
      fc.constantFrom(...simnet.getAccounts().values()),
      fc.nat(),
      (account: string, reward_cycle: number) => {
        // Arrange
        const { result: pox_4_info } = simnet.callReadOnlyFn(
          "pox-4",
          "get-pox-info",
          [],
          account,
        );
        assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
        assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
        const first_burnchain_block_height =
          pox_4_info.value.data["first-burnchain-block-height"];
        const reward_cycle_length =
          pox_4_info.value.data["reward-cycle-length"];

        // Act
        const { result: actual } = simnet.callReadOnlyFn(
          "signers-voting",
          "reward-cycle-to-burn-height",
          [Cl.uint(reward_cycle)],
          account,
        );

        // Assert
        assert(isClarityType(reward_cycle_length, ClarityType.UInt));
        assert(isClarityType(first_burnchain_block_height, ClarityType.UInt));
        const expected = (reward_cycle * Number(reward_cycle_length.value)) +
          Number(first_burnchain_block_height.value);
        expect(actual).toBeUint(expected);
      },
    ),
    { numRuns: 250 },
  );
});

it("should return correct burn-height-to-reward-cycle", () => {
  fc.assert(
    fc.property(
      fc.constantFrom(...simnet.getAccounts().values()),
      fc.nat(),
      (account: string, height: number) => {
        // Arrange
        const { result: pox_4_info } = simnet.callReadOnlyFn(
          "pox-4",
          "get-pox-info",
          [],
          account,
        );
        assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
        assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
        const first_burnchain_block_height =
          pox_4_info.value.data["first-burnchain-block-height"];
        const reward_cycle_length =
          pox_4_info.value.data["reward-cycle-length"];

        // Act
        const { result: actual } = simnet.callReadOnlyFn(
          "signers-voting",
          "burn-height-to-reward-cycle",
          [Cl.uint(height)],
          account,
        );

        // Assert
        assert(isClarityType(first_burnchain_block_height, ClarityType.UInt));
        assert(isClarityType(reward_cycle_length, ClarityType.UInt));
        const expected = Math.floor(
          (height - Number(first_burnchain_block_height.value)) /
            Number(reward_cycle_length.value),
        );
        expect(actual).toBeUint(expected);
      },
    ),
    { numRuns: 250 },
  );
});

it("should return correct is-in-prepare-phase", () => {
  fc.assert(
    fc.property(
      fc.constantFrom(...simnet.getAccounts().values()),
      fc.nat(),
      (account: string, height: number) => {
        // Arrange
        const { result: pox_4_info } = simnet.callReadOnlyFn(
          "pox-4",
          "get-pox-info",
          [],
          account,
        );
        assert(isClarityType(pox_4_info, ClarityType.ResponseOk));
        assert(isClarityType(pox_4_info.value, ClarityType.Tuple));
        const first_burnchain_block_height =
          pox_4_info.value.data["first-burnchain-block-height"];
        const prepare_cycle_length =
          pox_4_info.value.data["prepare-cycle-length"];
        const reward_cycle_length =
          pox_4_info.value.data["reward-cycle-length"];

        // Act
        const { result: actual } = simnet.callReadOnlyFn(
          "signers-voting",
          "is-in-prepare-phase",
          [Cl.uint(height)],
          account,
        );

        // Assert
        assert(isClarityType(first_burnchain_block_height, ClarityType.UInt));
        assert(isClarityType(prepare_cycle_length, ClarityType.UInt));
        assert(isClarityType(reward_cycle_length, ClarityType.UInt));
        const expected = ((height - Number(first_burnchain_block_height.value) +
          Number(prepare_cycle_length.value)) %
          Number(reward_cycle_length.value)) <
          Number(prepare_cycle_length.value);
        expect(actual).toBeBool(expected);
      },
    ),
    { numRuns: 250 },
  );
});
