import { ParsedTransactionResult, tx } from "@hirosystems/clarinet-sdk";
import { Cl, ClarityType, cvToString } from "@stacks/transactions";
import { describe, expect, it } from "vitest";
import {
  FunctionAnnotations,
  extractTestAnnotations,
} from "./utils/clarity-parser";
import { isValidTestFunction } from "./utils/test-helpers";

function isTestContract(contractName: string) {
  return (
    contractName.substring(contractName.length - 5) === "_test" &&
    contractName.substring(contractName.length - 10) !== "_flow_test"
  );
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
      const annotations: any = extractTestAnnotations(source);
      const functionAnnotations: FunctionAnnotations =
        annotations[functionName] || {};

      const mineBlocksBefore =
        parseInt(annotations["mine-blocks-before"] as string) || 0;

      it(`${functionCall.name}${
        functionAnnotations.name ? `: ${functionAnnotations.name}` : ""
      }`, () => {
        if (hasDefaultPrepareFunction && !functionAnnotations.prepare)
          functionAnnotations.prepare = "prepare";
        if (functionAnnotations["no-prepare"])
          delete functionAnnotations.prepare;

        const callerAddress = functionAnnotations.caller
          ? annotations.caller[0] === "'"
            ? `${(annotations.caller as string).substring(1)}`
            : accounts.get(annotations.caller)!
          : accounts.get("deployer")!;

        if (functionAnnotations.prepare) {
          mineBlockWithPrepareAndTestFunctionCall(
            contractFQN,
            functionAnnotations.prepare as string,
            mineBlocksBefore,
            functionName,
            callerAddress
          );
        } else {
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

function expectOkTrue(
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
