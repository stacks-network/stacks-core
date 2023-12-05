import { ParsedTransactionResult } from "@hirosystems/clarinet-sdk";
import { Cl, ClarityType, cvToString } from "@stacks/transactions";
import { expect } from "vitest";

/**
 * checks whether the function is a valid test function starting with "test-"
 * and not having any arguments
 * @param functionCall
 * @returns
 */
export function isValidTestFunction(functionCall: any) {
  if (functionCall.name.startsWith("test-") && functionCall.args.length > 0) {
    throw new Error("test functions must not have arguments");
  }
  return (
    functionCall.name.startsWith("test-") && functionCall.args.length === 0
  );
}

/**
 * expect the result of tx index in the given block to be (ok true)
 * @param block 
 * @param contractFQN 
 * @param functionName 
 * @param index 
 */
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

/**
 * expect the result of tx index in the given block to be succesfull (ok ...)
 * @param block 
 * @param contractFQN 
 * @param functionName 
 * @param index 
 */
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
