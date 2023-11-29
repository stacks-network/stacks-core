import { ParsedTransactionResult } from "@hirosystems/clarinet-sdk";
import { Cl, ClarityType, cvToString } from "@stacks/transactions";
import { expect } from "vitest";

export function isValidTestFunction(functionCall: any) {
  if (functionCall.name.startsWith("test-") && functionCall.args.length > 0) {
    throw new Error("test functions must not have arguments");
  }
  return (
    functionCall.name.startsWith("test-") && functionCall.args.length === 0
  );
}

export function expectOkTrue(
  block: ParsedTransactionResult[],
  contractFQN: string,
  functionName: string,
  index: number = 0
) {
  if (block[index].result.type === ClarityType.ResponseErr) {
    console.log(cvToString(block[index].result));
  }
  expect(
    block[index].result,
    `${contractFQN}, ${functionName}, ${cvToString(block[index].result)}`
  ).toBeOk(Cl.bool(true));
}

export function expectOk(
  block: ParsedTransactionResult[],
  contractFQN: string,
  functionName: string,
  index: number = 0
) {
  if (block[index].result.type === ClarityType.ResponseErr) {
    console.log(cvToString(block[index].result));
  }
  expect(
    block[index].result.type,
    `${contractFQN}, ${functionName}, ${cvToString(block[index].result)}`
  ).toBe(ClarityType.ResponseOk);
}
