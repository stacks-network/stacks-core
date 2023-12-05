import { tx } from "@hirosystems/clarinet-sdk";
import { describe, it } from "vitest";
import {
  FunctionAnnotations,
  extractTestAnnotations,
} from "./utils/clarity-parser";
import { expectOkTrue, isValidTestFunction } from "./utils/test-helpers";

/**
 * Returns true if the contract is a test contract
 * @param contractName name of the contract
 * @returns 
 */
function isTestContract(contractName: string) {
  return (
    contractName.substring(contractName.length - 5) === "_test" &&
    contractName.substring(contractName.length - 10) !== "_flow_test"
  );
}

const accounts = simnet.getAccounts();

// for each test contract create a test suite
simnet.getContractsInterfaces().forEach((contract, contractFQN) => {
  if (!isTestContract(contractFQN)) {
    return;
  }

  describe(contractFQN, () => {
    // determine whether the contract has a prepare function
    const hasDefaultPrepareFunction =
      contract.functions.findIndex((f) => f.name === "prepare") >= 0;

    contract.functions.forEach((functionCall) => {
      if (!isValidTestFunction(functionCall)) {
        return;
      }

      const functionName = functionCall.name;
      const source = simnet.getContractSource(contractFQN)!;
      const annotations: any = extractTestAnnotations(source);
      const functionAnnotations: FunctionAnnotations =
        annotations[functionName] || {};

      const mineBlocksBefore =
        parseInt(annotations["mine-blocks-before"] as string) || 0;

      const testDescription = `${functionCall.name}${
        functionAnnotations.name ? `: ${functionAnnotations.name}` : ""
      }`;
      it(testDescription, () => {
        // handle prepare function for this test
        if (hasDefaultPrepareFunction && !functionAnnotations.prepare)
          functionAnnotations.prepare = "prepare";
        if (functionAnnotations["no-prepare"])
          delete functionAnnotations.prepare;

        // handle caller address for this test
        const callerAddress = functionAnnotations.caller
          ? annotations.caller[0] === "'"
            ? `${(annotations.caller as string).substring(1)}`
            : accounts.get(annotations.caller)!
          : accounts.get("deployer")!;

        if (functionAnnotations.prepare) {
          // mine block with prepare function call
          mineBlockWithPrepareAndTestFunctionCall(
            contractFQN,
            functionAnnotations.prepare as string,
            mineBlocksBefore,
            functionName,
            callerAddress
          );
        } else {
          // mine block without prepare function call
          mineBlockWithTestFunctionCall(
            contractFQN,
            mineBlocksBefore,
            functionName,
            callerAddress
          );
        }
      });
    });
  });
});

/**
 * Mine a block with a prepare function call and a test function call
 * If requested, mine the specified number of blocks beforehand.
 * @param contractFQN the contract id of the test
 * @param prepareFunctionName the function name of the prepare function
 * @param mineBlocksBefore the number of blocks to mine before the prepare function call, can be 0
 * @param functionName the test function name
 * @param callerAddress the caller of the test function
 */
function mineBlockWithPrepareAndTestFunctionCall(
  contractFQN: string,
  prepareFunctionName: string,
  mineBlocksBefore: number,
  functionName: string,
  callerAddress: string
) {
  if (mineBlocksBefore > 0) {
    let block = simnet.mineBlock([
      tx.callPublicFn(
        contractFQN,
        prepareFunctionName,
        [],
        accounts.get("deployer")!
      ),
    ]);
    expectOkTrue(block, contractFQN, prepareFunctionName, 0);
    simnet.mineEmptyBlocks(mineBlocksBefore - 1);

    block = simnet.mineBlock([
      tx.callPublicFn(contractFQN, functionName, [], callerAddress),
    ]);

    expectOkTrue(block, contractFQN, functionName, 0);
  } else {
    let block = simnet.mineBlock([
      tx.callPublicFn(
        contractFQN,
        prepareFunctionName,
        [],
        accounts.get("deployer")!
      ),
      tx.callPublicFn(contractFQN, functionName, [], callerAddress),
    ]);
    expectOkTrue(block, contractFQN, prepareFunctionName, 0);
    expectOkTrue(block, contractFQN, functionName, 1);
  }
}

/**
 * Mines a block with a single test function call
 * If requested, mine the specified number of blocks beforehand.
 *
 * @param contractFQN the contract id of the test
 * @param mineBlocksBefore the number of blocks to mine before the test function call, can be 0
 * @param functionName the test function name
 * @param callerAddress the caller of the test function
 */
function mineBlockWithTestFunctionCall(
  contractFQN: string,
  mineBlocksBefore: number,
  functionName: string,
  callerAddress: string
) {
  simnet.mineEmptyBlocks(mineBlocksBefore);
  const block = simnet.mineBlock([
    tx.callPublicFn(contractFQN, functionName, [], callerAddress),
  ]);
  expectOkTrue(block, contractFQN, functionName, 0);
}
