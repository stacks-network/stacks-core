import path from 'path';
import { executeCommand } from './processUtil';

// TODO: configurable node src dir
export function getCoreSrcDir() {
  const dir = path.resolve(__dirname, '../../');
  return dir;
}

/**
 * Use cargo to build the Blockstack node rust src, which is expected to be in the current repo directory.
 */
export async function cargoBuild() {
  const coreSrcDir = getCoreSrcDir();
  const args = ['build', '--bin=blockstack-core', '--package=blockstack-core'];
  const result = await executeCommand('cargo', args, {
    cwd: coreSrcDir
  });
  return result;
}

/**
 * Run command against a local Blockstack node VM.
 * Uses `cargo run` with the rust src expected in the current repo dir.
 * @param localArgs Local test node commands.
 */
export async function cargoRunLocal(
  localArgs: string[],
  opts?: { stdin: string }
) {
  const coreSrcDir = getCoreSrcDir();
  const args = [
    'run',
    '--bin=blockstack-core',
    '--package=blockstack-core',
    '--',
    'local',
    ...localArgs
  ];
  const result = await executeCommand('cargo', args, {
    cwd: coreSrcDir,
    stdin: opts && opts.stdin
  });
  // Normalize first EOL, and trim last EOL.
  result.stdout = result.stdout
    .replace(/\r\n|\r|\n/, '\n')
    .replace(/\r\n|\r|\n$/, '');
  return result;
}

export async function cargoEvalStatement(
  contractName: string,
  evalStatement: string,
  dbFile: string
): Promise<string> {
  const result = await cargoRunLocal(['eval', contractName, dbFile], {
    stdin: evalStatement
  });
  if (result.exitCode !== 0) {
    throw new Error(
      `Eval exited with code: ${result.exitCode}: ${result.stdout}`
    );
  }
  // Check and trim success prefix line.
  const successPrefix = result.stdout.match(
    /(Program executed successfully! Output: (\r\n|\r|\n))/
  );
  if (successPrefix.length < 1) {
    throw new Error(`Bad eval output: ${result.stdout}`);
  }
  // Get the output string with the prefix message and last EOL trimmed.
  let outputResult = result.stdout.substr(successPrefix[0].length);
  outputResult = outputResult.replace(/\r\n|\r|\n$/, '');
  if (outputResult[0] !== ' ') {
    throw new Error(
      `Eval output line is not left padded with a space: ${outputResult}`
    );
  }
  outputResult = outputResult.substring(1);
  return outputResult;
}

/*
export interface LocalNodeExecutor {
  
}
*/
