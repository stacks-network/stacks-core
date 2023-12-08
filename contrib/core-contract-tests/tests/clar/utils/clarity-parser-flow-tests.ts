import { ClarityValue } from "@stacks/transactions";
import { stringToCV } from "./string-to-cv";
export type FunctionAnnotations = { [key: string]: string | boolean };
export type FunctionBody = {
  callAnnotations: FunctionAnnotations[];
  callInfo: CallInfo;
}[];

export type ContractCall = {
  callAnnotations: FunctionAnnotations;
  callInfo: CallInfo;
};

export type CallInfo = {
  contractName: string;
  functionName: string;
  args: { type: string; value: ClarityValue }[];
};

const functionRegex =
  /^([ \t]{0,};;[ \t]{0,}@[^()]+?)\n[ \t]{0,}\(define-public[\s]+\((.+?)[ \t|)]/gm;
const annotationsRegex = /^;;[ \t]{1,}@([a-z-]+)(?:$|[ \t]+?(.+?))$/;

const callRegex =
  /\n*^([ \t]{0,};;[ \t]{0,}@[\s\S]+?)\n[ \t]{0,}(\((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*\))/gm;

/**
 * Parser function for flow unit tests.
 *
 * Flow unit tests can be used for tx calls where
 * the tx-sender should be equal to the contract-caller.
 *
 * Takes the whole contract source and returns an object containing
 * the function annotations and function bodies for each function.
 * @param contractSource
 * @returns
 */
export function extractTestAnnotationsAndCalls(contractSource: string) {
  const functionAnnotations: any = {};
  const functionBodies: any = {};
  contractSource = contractSource.replace(/\r/g, "");
  const matches1 = contractSource.matchAll(functionRegex);

  let indexStart: number = -1;
  let headerLength: number = 0;
  let indexEnd: number = -1;
  let lastFunctionName: string = "";
  let contractCalls: {
    callAnnotations: FunctionAnnotations;
    callInfo: CallInfo;
  }[];
  for (const [functionHeader, comments, functionName] of matches1) {
    if (functionName.substring(0, 5) !== "test-") continue;
    functionAnnotations[functionName] = {};
    const lines = comments.split("\n");
    for (const line of lines) {
      const [, prop, value] = line.match(annotationsRegex) || [];
      if (prop) functionAnnotations[functionName][prop] = value ?? true;
    }
    if (indexStart < 0) {
      indexStart = contractSource.indexOf(functionHeader);
      headerLength = functionHeader.length;
      lastFunctionName = functionName;
    } else {
      indexEnd = contractSource.indexOf(functionHeader);
      const lastFunctionBody = contractSource.substring(
        indexStart + headerLength,
        indexEnd
      );

      // add contracts calls in functions body for last function
      contractCalls = extractContractCalls(lastFunctionBody);

      functionBodies[lastFunctionName] = contractCalls;
      indexStart = indexEnd;
      headerLength = functionHeader.length;
      lastFunctionName = functionName;
    }
  }
  const lastFunctionBody = contractSource.substring(indexStart + headerLength);
  contractCalls = extractContractCalls(lastFunctionBody);
  functionBodies[lastFunctionName] = contractCalls;

  return [functionAnnotations, functionBodies];
}

/**
 * Takes a string and returns an array of objects containing
 * the call annotations and call info within the function body.
 *
 * The function body should look like this
 * (begin
 *   ... lines of code..
 *   (ok true))
 *
 * Only two lines of code are accepted:
 * 1. (unwrap! (contract-call? .contract-name function-name args))
 * 2. (try! (function-name))
 * @param lastFunctionBody
 * @returns
 */
export function extractContractCalls(lastFunctionBody: string) {
  const calls = lastFunctionBody.matchAll(callRegex);
  const contractCalls: ContractCall[] = [];
  for (const [, comments, call] of calls) {
    const callAnnotations: FunctionAnnotations = {};
    const lines = comments.split("\n");
    for (const line of lines) {
      const [, prop, value] = line.trim().match(annotationsRegex) || [];
      if (prop) callAnnotations[prop] = value ?? true;
    }
    // try to extract call info from (unwrap! (contract-call? ...))
    let callInfo = extractUnwrapInfo(call);
    if (!callInfo) {
      // try to extract call info from (try! (my-function))
      callInfo = extractCallInfo(call);
    }
    if (callInfo) {
      contractCalls.push({ callAnnotations, callInfo });
    } else {
      throw new Error(`Could not extract call info from ${call}`);
    }
  }
  return contractCalls;
}

/**
 * handle (unwrap! (contract-call? ...)) statements
 * @param statement 
 * @returns 
 */
function extractUnwrapInfo(statement: string): CallInfo | null {
  const match = statement.match(
    /\(unwrap! \(contract-call\? \.(.+?) (.+?)(( .+?)*)\)/
  );
  if (!match) return null;

  const contractName = match[1];
  const functionName = match[2];
  const argStrings = splitArgs(match[3]);
  let fn: any;
  simnet.getContractsInterfaces().forEach((contract, contractFQN) => {
    const [_, ctrName] = contractFQN.split(".");
    if (ctrName === contractName) {
      fn = contract.functions.find((f) => f.name === functionName);
      if (!fn) {
        throw `function ${functionName} not found in contract ${contractName}`;
      }
    }
  });
  if (!fn) {
    throw `function ${functionName} not found in contract ${contractName}`;
  }
  const args = fn.args.map((arg: any, index: number) =>
  stringToCV(argStrings[index], arg.type)
  );

  return {
    contractName,
    functionName,
    args,
  };
}


function extractCallInfo(statement: string) {
  const match = statement.match(/\(try! \((.+?)\)\)/);
  if (!match) return null;
  return { contractName: "", functionName: match[1], args: [] };
}



// take a string containing function arguments and
// split them correctly into an array of argument strings
function splitArgs(argString: string): string[] {
  const splitArgs: string[] = [];
  let argStart = 0;
  let brackets = 0; // curly brackets
  let rbrackets = 0; // round brackets

  for (let i = 0; i < argString.length; i++) {
    const char = argString[i];

    if (char === "{") brackets++;
    if (char === "}") brackets--;
    if (char === "(") rbrackets++;
    if (char === ")") rbrackets--;

    const atLastChar = i === argString.length - 1;
    if ((char === " " && brackets === 0 && rbrackets === 0) || atLastChar) {
      const newArg = argString.slice(argStart, i + (atLastChar ? 1 : 0));
      if (newArg.trim()) {
        splitArgs.push(newArg.trim());
      }
      argStart = i + 1;
    }
  }

  return splitArgs;
}
