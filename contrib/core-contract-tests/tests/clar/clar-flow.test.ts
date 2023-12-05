import { ParsedTransactionResult, tx } from "@hirosystems/clarinet-sdk";
import * as fs from "fs";
import path from "path";
import { describe, it } from "vitest";
import {
  CallInfo,
  FunctionAnnotations,
  FunctionBody,
  extractTestAnnotationsAndCalls,
} from "./utils/clarity-parser-flow-tests";
import { expectOk, isValidTestFunction } from "./utils/test-helpers";

/**
 * Returns true if the contract is a test contract using the flow convention
 * @param contractName name of the contract
 * @returns
 */
function isTestContract(contractName: string) {
  return contractName.substring(contractName.length - 10) === "_flow_test";
}

const accounts = simnet.getAccounts();
clearLogFile();

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
      const [annotations, functionBodies] =
        extractTestAnnotationsAndCalls(source);
      const functionAnnotations: FunctionAnnotations =
        annotations[functionName] || {};
      const testname = `${functionCall.name}${
        functionAnnotations.name ? `: ${functionAnnotations.name}` : ""
      }`;
      it(testname, () => {
        writeToLogFile(`\n\n${testname}\n\n`);
        if (hasDefaultPrepareFunction && !functionAnnotations.prepare)
          functionAnnotations.prepare = "prepare";
        if (functionAnnotations["no-prepare"])
          delete functionAnnotations.prepare;

        const functionBody = functionBodies[functionName] || [];

        mineBlocksFromFunctionBody(contractFQN, functionName, functionBody);
      });
    });
  });
});

/**
 * Mines one or more blocks based on the functions calls in the test function.
 * The function body must be one of the following:
 * 1. (unwrap! (contract-call? .contract-name function-name args))
 * 2. (try! (function-name))
 *
 * @param contractFQN the contract id
 * @param testFunctionName the name of the test function containing calls
 * @param calls a list of function calls with annotations part of the test function body
 */
function mineBlocksFromFunctionBody(
  contractFQN: string,
  testFunctionName: string,
  calls: FunctionBody
) {
  let blockStarted = false;
  let txs: any[] = [];
  let block: ParsedTransactionResult[] = [];

  // go through all function calls and
  // bundle function them into blocks
  for (const { callAnnotations, callInfo } of calls) {
    // mine empty blocks
    const mineBlocksBefore =
      parseInt(callAnnotations["mine-blocks-before"] as string) || 0;
    // get caller address
    const caller = accounts.get(
      (callAnnotations["caller"] as string) || "deployer"
    )!;

    if (mineBlocksBefore >= 1) {
      if (blockStarted) {
        writeToLogFile(txs);
        // mine block with txs and assert ok on all of them
        block = simnet.mineBlock(txs);
        for (let index = 0; index < txs.length; index++) {
          expectOk(block, contractFQN, testFunctionName, index);
        }
        txs = [];
        blockStarted = false;
      }
      // mine empty blocks if necessary
      if (mineBlocksBefore > 1) {
        simnet.mineEmptyBlocks(mineBlocksBefore - 1);
        writeToLogFile(mineBlocksBefore - 1);
      }
    }
    // start a new block if necessary
    if (!blockStarted) {
      blockStarted = true;
    }
    // add tx to current block
    txs.push(generateCallWithArguments(callInfo, contractFQN, caller));
  }
  // close final block
  if (blockStarted) {
    writeToLogFile(txs);
    block = simnet.mineBlock(txs);
    for (let index = 0; index < txs.length; index++) {
      expectOk(block, contractFQN, testFunctionName, index);
    }
    txs = [];
    blockStarted = false;
  }
}

/**
 * creates a Tx
 * @param callInfo
 * @param contractPrincipal
 * @param callerAddress
 * @returns
 */
function generateCallWithArguments(
  callInfo: CallInfo,
  contractPrincipal: string,
  callerAddress: string
) {
  const contractName = callInfo.contractName || contractPrincipal;
  const functionName = callInfo.functionName;

  return tx.callPublicFn(
    contractName,
    functionName,
    callInfo.args.map((arg) => arg.value),
    callerAddress
  );
}

/**
 * writes data to a log file that represents the sequence of blocks mined
 * @param data
 */
function writeToLogFile(data: ParsedTransactionResult[] | number | string) {
  const filePath = path.join(__dirname, "clar-flow-test.log.txt");
  if (typeof data === "number") {
    fs.appendFileSync(filePath, `${data} empty blocks\n`);
  } else if (typeof data === "string") {
    fs.appendFileSync(filePath, `${data}\n`);
  } else {
    fs.appendFileSync(filePath, `block:\n${JSON.stringify(data, null, 2)}\n`);
  }
}

/**
 * clears the log file
 */
function clearLogFile() {
  const filePath = path.join(__dirname, "clar-flow-test.log.txt");
  fs.writeFileSync(filePath, "");
}
