import { describe, expect, it } from "vitest";
import * as fs from "fs";
import path from "path";
import { extractTestAnnotations } from "./utils/clarity-parser";

describe("verify clarity parser", () => {
  it("should parse without annotations", () => {
    const result = extractTestAnnotations(
      fs.readFileSync(
        path.join(
          __dirname,
          "../../contracts/parser-tests/no-annotations.clar"
        ),
        "utf8"
      )
    );
    expect(result).toEqual({});
  });

  it("should parse with simple annotations", () => {
    const result = extractTestAnnotations(
      fs.readFileSync(
        path.join(
          __dirname,
          "../../contracts/parser-tests/simple-annotations.clar"
        ),
        "utf8"
      )
    );
    expect(result["test-simple-annotations"]).toEqual({
      name: "simple annotation test",
    });
  });

  it("should parse with all annotations", () => {
    const result = extractTestAnnotations(
      fs.readFileSync(
        path.join(
          __dirname,
          "../../contracts/parser-tests/all-annotations.clar"
        ),
        "utf8"
      )
    );
    expect(result["test-all-annotations-1"]).toEqual({
      caller: "wallet_1",
      description: "all annotation test",
      "mine-before": "10",
      name: "all annotation test",
    });

    expect(result["test-all-annotations-2"]).toEqual({
      caller: "wallet_2",
      description: "all annotation test 2",
      "mine-before": "20",
      name: "all annotation test 2",
    });
  });

  it("should parse with bad annotations", () => {
    const result = extractTestAnnotations(
      fs.readFileSync(
        path.join(
          __dirname,
          "../../contracts/parser-tests/bad-annotations.clar"
        ),
        "utf8"
      )
    );
    expect(result["test-bad-annotations"]).toEqual({
      namexx: "bad annotation test",
      callerxx: "wallet_1",
      "mine-after": "10",
    });
  });
});
