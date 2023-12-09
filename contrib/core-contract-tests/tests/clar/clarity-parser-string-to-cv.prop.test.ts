import { describe, expect, it } from "vitest";
import { stringToCV } from "./utils/string-to-cv";
import { ClarityType, intCV, stringUtf8CV, uintCV } from "@stacks/transactions";
import fc from "fast-check";

const uint128 = fc
  .tuple(fc.bigUintN(64), fc.bigUintN(64))
  .map(([hi, lo]) => (hi << BigInt(64)) | lo);

const int128 = fc
  .tuple(fc.bigIntN(64), fc.bigIntN(64))
  .map(([hi, lo]) => (hi << BigInt(64)) | lo);

describe("verify string to cv conversion", () => {
  it("should convert string to cv", () => {
    fc.assert(fc.property(fc.string(), (someStr) => {
      const result = stringToCV(someStr, { "string-utf8": { length: 100 } });
      expect(result).toEqual({
        type: "string",
        value: stringUtf8CV(someStr),
      });
    }));
  });

  it("should convert uint to cv", () => {
    fc.assert(fc.property(uint128, (someUInt) => {
      const result = stringToCV(`u${someUInt}`, "uint128");
      expect(result).toEqual({
        type: "uint",
        value: uintCV(someUInt),
      });
    }));
  });

  it("should convert tuple to cv", () => {
    fc.assert(fc.property(fc.record({
      key: fc.stringMatching(/^[a-zA-Z][a-zA-Z0-9]{0,9}$/),
      val: int128 }), (r) => {
      const result = stringToCV(`{${r.key}: ${r.val}}`, {
        tuple: [{ name: r.key, type: "int128" }],
      });
      expect(result).toEqual({
        type: "tuple",
        value: { data: { [r.key]: intCV(r.val) }, type: ClarityType.Tuple },
      });
    }));
  });
});

describe("custom arbitraries for 128-bit unsigned/signed integers", () => {
  it("generates 128-bit unsigned integers in range [0, 2^128 - 1]", () => {
    fc.assert(fc.property(uint128, (actual) =>
      actual >= BigInt(0) &&
      actual <= BigInt("340282366920938463463374607431768211455")
    ));
  });

  it("generates 128-bit signed integers in range [-2^127, 2^127 - 1]", () => {
    fc.assert(fc.property(int128, (actual) =>
      actual >= BigInt("-170141183460469231731687303715884105728") &&
      actual <= BigInt( "170141183460469231731687303715884105727")
    ));
  });
});
