const functionRegex =
  /^([ \t]{0,};;[ \t]{0,}@[^()]+?)\n[ \t]{0,}\(define-public[\s]+\((.+?)[ \t|)]/gm;
const annotationsRegex = /^;;[ \t]{1,}@([a-z-]+)(?:$|[ \t]+?(.+?))$/;

/**
 * Parser function for normal unit tests.
 *
 * Takes the whole contract source and returns an object containing
 * the function annotations for each function
 * @param contractSource
 * @returns
 */
export function extractTestAnnotations(contractSource: string) {
  const functionAnnotations: any = {};
  const matches = contractSource.replace(/\r/g, "").matchAll(functionRegex);
  for (const [, comments, functionName] of matches) {
    functionAnnotations[functionName] = {};
    const lines = comments.split("\n");
    for (const line of lines) {
      const [, prop, value] = line.match(annotationsRegex) || [];
      if (prop) functionAnnotations[functionName][prop] = value ?? true;
    }
  }
  return functionAnnotations;
}
