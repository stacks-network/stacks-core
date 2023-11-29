import { ParsedTransactionResult, tx } from "@hirosystems/clarinet-sdk";
import { describe, it } from "vitest";
import {
  CallInfo,
  FunctionAnnotations,
  FunctionBody,
  extractTestAnnotationsAndCalls,
} from "./utils/clarity-parser";
import { expectOk, isValidTestFunction } from "./utils/test-helpers";

function isTestContract(contractName: string) {
  return contractName.substring(contractName.length - 10) === "_flow_test";
}

const accounts = simnet.getAccounts();
simnet.getContractsInterfaces().forEach((contract, contractFQN) => {
  if (!isTestContract(contractFQN)) {
    return;
  }

  describe(contractFQN, () => {
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

      it(`${functionCall.name}${
        functionAnnotations.name ? `: ${functionAnnotations.name}` : ""
      }`, () => {
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
function mineBlocksFromFunctionBody(
  contractFQN: string,
  testFunctionName: string,
  calls: FunctionBody
) {
  let blockStarted = false;
  let txs: any[] = [];
  let block: ParsedTransactionResult[] = [];

  for (const { callAnnotations, callInfo } of calls) {
    // mine empty blocks
    const mineBlocksBefore =
      parseInt(callAnnotations["mine-blocks-before"] as string) || 0;
    const caller = accounts.get(
      (callAnnotations["caller"] as string) || "deployer"
    )!;

    if (mineBlocksBefore >= 1) {
      if (blockStarted) {
        console.log(txs);
        block = simnet.mineBlock(txs);
        for (let index = 0; index < txs.length; index++) {
          expectOk(block, contractFQN, testFunctionName, index);
        }
        txs = [];
        blockStarted = false;
      }
      if (mineBlocksBefore > 1) {
        simnet.mineEmptyBlocks(mineBlocksBefore - 1);
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
    console.log(txs);
    block = simnet.mineBlock(txs);
    for (let index = 0; index < txs.length; index++) {
      expectOk(block, contractFQN, testFunctionName, index);
    }
    txs = [];
    blockStarted = false;
  }
}

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
