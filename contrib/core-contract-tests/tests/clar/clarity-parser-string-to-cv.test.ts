import { describe, expect, it } from "vitest";
import { stringToCV } from "./utils/string-to-cv";
import { ClarityType, intCV, stringUtf8CV, uintCV } from "@stacks/transactions";

describe("verify string to cv conversion", () => {
  it("should convert string to cv", () => {
    const result = stringToCV("hello", { "string-utf8": { length: 100 } });
    expect(result).toEqual({
      type: "string",
      value: stringUtf8CV("hello"),
    });
  });

  it("should convert uint to cv", () => {
    const result = stringToCV("u12345", "uint128");
    expect(result).toEqual({
      type: "uint",
      value: uintCV(12345),
    });
  });

  it("should convert tuple to cv", () => {
    const result = stringToCV("{a: 12345}", {
      tuple: [{ name: "a", type: "int128" }],
    });
    expect(result).toEqual({
      type: "tuple",
      value: { data: { a: intCV(12345) }, type: ClarityType.Tuple },
    });
  });
});
