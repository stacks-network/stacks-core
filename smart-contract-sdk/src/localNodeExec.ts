import path from 'path';
import { executeCommand } from './processUtil';

export class LocalExecutionError extends Error {
  readonly code: number;
  readonly commandOutput: string;
  readonly errorOutput: string;
  constructor(
    message: string,
    code: number,
    commandOutput: string,
    errorOutput: string
  ) {
    super(message);
    this.message = message;
    this.name = this.constructor.name;
    this.code = code;
    this.commandOutput = commandOutput;
    this.errorOutput = errorOutput;
    Error.captureStackTrace(this, this.constructor);
  }
}

export interface LocalNodeExecutor {
  initialize(): Promise<void>;
  checkContract(contractFilePath: string): Promise<void>;
  deployContract(contractName: string, contractFilePath: string): Promise<void>;
  executeStatement(contractName: string, ...statement: string[]): Promise<void>;
  evalStatement(contractName: string, evalStatement: string): Promise<string>;
}

export class CargoLocalNodeExecutor implements LocalNodeExecutor {
  readonly dbFilePath: string;
  readonly coreSrcDir: string;

  static getCoreSrcDir() {
    const dir = path.resolve(__dirname, '../../');
    return dir;
  }

  constructor(
    dbFilePath: string,
    coreSrcDir = CargoLocalNodeExecutor.getCoreSrcDir()
  ) {
    this.dbFilePath = dbFilePath;
    this.coreSrcDir = coreSrcDir;
  }

  /**
   * Use cargo to build the Blockstack node rust src.
   */
  async cargoBuild() {
    const args = [
      'build',
      '--bin=blockstack-core',
      '--package=blockstack-core'
    ];
    const result = await executeCommand('cargo', args, {
      cwd: this.coreSrcDir
    });
    if (result.exitCode !== 0) {
      throw new Error(`Cargo build failed: ${result.stderr}, ${result.stdout}`);
    }
  }

  /**
   * Run command against a local Blockstack node VM.
   * Uses `cargo run` with the configured rust src.
   * @param localArgs Local test node commands.
   */
  async cargoRunLocal(localArgs: string[], opts?: { stdin: string }) {
    const args = [
      'run',
      '--bin=blockstack-core',
      '--package=blockstack-core',
      '--quiet',
      '--',
      'local',
      ...localArgs
    ];
    const result = await executeCommand('cargo', args, {
      cwd: this.coreSrcDir,
      stdin: opts && opts.stdin
    });

    // Normalize first EOL, and trim last EOL.
    result.stdout = result.stdout
      .replace(/\r\n|\r|\n/, '\n')
      .replace(/\r\n|\r|\n$/, '');

    // Normalize all stderr EOLs, trim last EOL.
    result.stderr = result.stderr
      .replace(/\r\n|\r|\n/g, '\n')
      .replace(/\r\n|\r|\n$/, '');

    return result;
  }

  async initialize(): Promise<void> {
    const result = await this.cargoRunLocal(['initialize', this.dbFilePath]);
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Initialize failed with bad exit code: ${result.exitCode}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    if (result.stdout !== 'Database created.') {
      throw new LocalExecutionError(
        `Initialize failed with bad output: ${result.stdout}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
  }

  async checkContract(contractFilePath: string): Promise<void> {
    const result = await this.cargoRunLocal([
      'check',
      contractFilePath,
      this.dbFilePath
    ]);
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Check contract failed with bad exit code: ${result.exitCode}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
  }

  async deployContract(
    contractName: string,
    contractFilePath: string
  ): Promise<void> {
    const result = await this.cargoRunLocal([
      'launch',
      contractName,
      contractFilePath,
      this.dbFilePath
    ]);
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Launch contract failed with bad exit code: ${result.exitCode}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    if (result.stdout !== 'Contract initialized!') {
      throw new LocalExecutionError(
        `Launch contract failed with bad output: ${result.stdout}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
  }

  async executeStatement(
    contractName: string,
    ...statement: string[]
  ): Promise<void> {
    const result = await this.cargoRunLocal([
      'execute',
      this.dbFilePath,
      contractName,
      ...statement
    ]);
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Execute expression on contract failed with bad exit code: ${
          result.exitCode
        }`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    if (result.stdout !== 'Transaction executed and committed.') {
      throw new LocalExecutionError(
        `Execute expression on contract failed with bad output: ${
          result.stdout
        }`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
  }

  async evalStatement(
    contractName: string,
    evalStatement: string
  ): Promise<string> {
    const result = await this.cargoRunLocal(
      ['eval', contractName, this.dbFilePath],
      {
        stdin: evalStatement
      }
    );
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Eval expression on contract failed with bad exit code: ${
          result.exitCode
        }`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    // Check and trim success prefix line.
    const successPrefix = result.stdout.match(
      /(Program executed successfully! Output: (\r\n|\r|\n))/
    );
    if (successPrefix.length < 1) {
      throw new LocalExecutionError(
        `Eval expression on contract failed with bad output: ${result.stdout}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    // Get the output string with the prefix message and last EOL trimmed.
    let outputResult = result.stdout.substr(successPrefix[0].length);
    outputResult = outputResult.replace(/\r\n|\r|\n$/, '');
    if (outputResult[0] !== ' ') {
      throw new LocalExecutionError(
        `Eval expression on contract failed with unexpected output: ${outputResult}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    outputResult = outputResult.substring(1);
    return outputResult;
  }
}
