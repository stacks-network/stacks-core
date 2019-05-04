import { promisify } from 'util';
import { Readable, pipeline } from 'stream';
import { SpawnOptions, spawn } from 'child_process';
import { readStream } from './streamUtil';

const pipelineAsync = promisify(pipeline);

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface ExecuteOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdin?: Readable | string;
}

export async function executeCommand(
  command: string,
  args?: string[],
  opts?: ExecuteOptions
): Promise<ExecutionResult> {
  const spawnOpts: SpawnOptions = {};
  if (opts) {
    if (opts.cwd) {
      spawnOpts.cwd = opts.cwd;
    }
    if (opts.env) {
      spawnOpts.env = opts.env;
    }
  }
  const proc = spawn(command, args, spawnOpts);

  const readStdout = readStream(proc.stdout, true);
  const readStderr = readStream(proc.stderr, true);

  let writeStdin: Promise<void> = Promise.resolve();
  if (opts && opts.stdin) {
    if (typeof opts.stdin === 'string') {
      proc.stdin.end(opts.stdin, 'utf8');
    } else {
      writeStdin = pipelineAsync(opts.stdin, proc.stdin).catch((error: any) => {
        console.debug(`spawn stdin error: ${error}`);
      });
    }
  }

  proc.on('error', (error: any) => {
    console.error(`Unexpected process exec error: ${error}`);
  });

  const exitCode = await new Promise<number>(resolve => {
    proc.once('close', (code: number) => {
      resolve(code);
    });
  });

  const [stdoutData, stderrData] = await Promise.all([
    readStdout,
    readStderr,
    writeStdin
  ]);

  const stdoutStr = stdoutData.toString('utf8');
  const stderrStr = stderrData.toString('utf8');

  return {
    stdout: stdoutStr,
    stderr: stderrStr,
    exitCode: exitCode
  };
}
