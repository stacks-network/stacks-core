import { describe, it, expect } from "vitest";
import { extractTestAnnotations } from "./utils/clarity-parser";
import fc from "fast-check";

describe("verify clarity parser", () => {
  it("should handle arbitrary inputs gracefully without crashing", () => {
    fc.assert(fc.property(fc.string(), (arbitrary) => {
      const result = extractTestAnnotations(arbitrary);
      expect(result).toEqual({});
    }));
  });

  const generators = fc.record({
    // Generates a 'name' string that starts with a letter followed by up to 9
    // alphanumeric characters, and can optionally include up to two additional
    // words, each separated by a space and up to 10 characters long.
    "name": fc.stringMatching(/^[a-zA-Z][a-zA-Z0-9]{0,9}( [a-zA-Z0-9]{1,10}){0,2}$/),

    // Generates a 'description' string with the same pattern as 'name'.
    "description": fc.stringMatching(/^[a-zA-Z][a-zA-Z0-9]{0,9}( [a-zA-Z0-9]{1,10}){0,2}$/),

    // Generates a 'mineBefore' string representing the number of blocks before
    // a transaction is mined (as a positive integer).
    "mineBefore": fc.integer({ min: 1 }).map(String),

    // Generates a 'caller' string that is either "wallet_" followed by a number,
    // "faucet", or "deployer".
    "caller": fc.stringMatching(/^(wallet_\d+|faucet|deployer)$/),

    // Generates a 'functionName' string similar to 'name', but words are
    // separated by dashes instead of spaces.
    "functionName": fc.stringMatching(/^[a-zA-Z][a-zA-Z0-9]{0,9}(-[a-zA-Z0-9]{1,10}){0,2}$/),
  });

  it("should parse with simple annotations", () => {
    fc.assert(fc.property(generators, (expected) => {
      const result = extractTestAnnotations(
`
;; @name ${expected.name}
(define-public (${expected.functionName})
    ;; @mine-before is ignored here
    (ok true))
`
      );
      expect(result[expected.functionName]).toEqual({
        name: expected.name,
      });
    }));
  });

  it("should parse with all annotations", () => {
    fc.assert(fc.property(fc.array(generators), (array) => {
      const contractSource = array
        .map((expected) =>
`
;; @name ${expected.name}
;; @description ${expected.description}
;; @mine-before ${expected.mineBefore}
;; @caller ${expected.caller}
(define-public (${expected.functionName})
    (ok true))
`
        )
        .join();

      const result = extractTestAnnotations(contractSource);

      array.forEach(expected => {
        expect(result[expected.functionName]).toEqual({
          name         : expected.name,
          description  : expected.description,
          "mine-before": expected.mineBefore,
          caller       : expected.caller,
        });
      });
    }));
  });
});
