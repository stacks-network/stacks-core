import path from 'path';
import fs from 'fs';
import os from 'os';
import { executeCommand } from './processUtil';
import './globalUtil';
import { ContractTypes } from './ContractTypes';

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

export class LaunchedContract {
  readonly localNodeExecutor: LocalNodeExecutor;
  public readonly contractName: string;

  constructor(localNodeExecutor: LocalNodeExecutor, contractName: string) {
    this.localNodeExecutor = localNodeExecutor;
    this.contractName = contractName;
  }

  execute(
    functionName: string,
    senderAddress: string,
    ...args: string[]
  ): Promise<void> {
    return this.localNodeExecutor.execute(
      this.contractName,
      functionName,
      senderAddress,
      ...args
    );
  }

  eval(evalStatement: string): Promise<string> {
    return this.localNodeExecutor.eval(this.contractName, evalStatement);
  }
}

export interface CheckContractResult {
  isValid: boolean;
  message: string;
  code: number;
  contractTypes?: ContractTypes;
}

export interface LocalNodeExecutor {
  initialize(): Promise<void>;
  checkContract(contractFilePath: string): Promise<CheckContractResult>;
  launchContract(
    contractName: string,
    contractFilePath: string
  ): Promise<LaunchedContract>;
  execute(
    contractName: string,
    functionName: string,
    senderAddress: string,
    ...args: string[]
  ): Promise<void>;
  eval(contractName: string, evalStatement: string): Promise<string>;
  setBlockHeight(height: BigInt): Promise<void>;
  getBlockHeight(): Promise<BigInt>;
  close(): Promise<void>;
}

export function getTempDbPath() {
  const uniqueID = `${(Date.now() / 1000) | 0}-${Math.random()
    .toString(36)
    .substr(2, 6)}`;
  const dbFile = `blockstack-local-${uniqueID}.db`;
  return path.join(os.tmpdir(), dbFile);
}

export class CargoLocalNodeExecutor implements LocalNodeExecutor {
  public readonly dbFilePath: string;
  readonly coreSrcDir: string;
  private closeActions: (() => Promise<any>)[] = [];

  static getCoreSrcDir() {
    const dir = path.resolve(__dirname, '../../');
    return dir;
  }

  /**
   * Instantiates a new executor.
   * Before returning, ensures cargo is setup and working with `cargoBuild`,
   * and node is ready with `initialize`.
   */
  static async create(
    dbFilePath: string,
    coreSrcDir?: string
  ): Promise<CargoLocalNodeExecutor> {
    const executor = new CargoLocalNodeExecutor(dbFilePath, coreSrcDir);
    await executor.cargoBuild();
    await executor.initialize();
    return executor;
  }

  /**
   * Instantiates a new executor pointed at a new temporary database file.
   * The temp file is deleted when `close` is invoked.
   * Before returning, ensures cargo is setup and working with `cargoBuild`,
   * and node is ready with `initialize`.
   */
  static async createEphemeral(
    coreSrcDir?: string
  ): Promise<CargoLocalNodeExecutor> {
    const instance = await this.create(getTempDbPath(), coreSrcDir);
    instance.closeActions.push(() => fs.promises.unlink(instance.dbFilePath));
    return instance;
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

    // Normalize first EOL, and trim the trailing EOL.
    result.stdout = result.stdout
      .replace(/\r\n|\r|\n/, '\n')
      .replace(/\r\n|\r|\n$/, '');

    // Normalize all stderr EOLs, trim the trailing EOL.
    result.stderr = result.stderr
      .replace(/\r\n|\r|\n/g, '\n')
      .replace(/\r\n|\r|\n$/, '');

    return result;
  }

  async initialize(): Promise<void> {
    const result = await this.cargoRunLocal(['initialize', this.dbFilePath]);
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Initialize failed with bad exit code ${result.exitCode}: ${
          result.stderr
        }`,
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

  async checkContract(contractFilePath: string): Promise<CheckContractResult> {
    const result = await this.cargoRunLocal([
      'check',
      contractFilePath,
      this.dbFilePath,
      '--output_analysis'
    ]);
    if (result.exitCode !== 0) {
      return {
        isValid: false,
        message: result.stderr,
        code: result.exitCode
      };
    } else {
      const contractTypes = JSON.parse(result.stdout) as ContractTypes;
      return {
        isValid: true,
        message: result.stdout,
        code: result.exitCode,
        contractTypes: contractTypes
      };
    }
  }

  async launchContract(
    contractName: string,
    contractFilePath: string
  ): Promise<LaunchedContract> {
    const result = await this.cargoRunLocal([
      'launch',
      contractName,
      contractFilePath,
      this.dbFilePath
    ]);
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Launch contract failed with bad exit code ${result.exitCode}: ${
          result.stderr
        }`,
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
    return new LaunchedContract(this, contractName);
  }

  async execute(
    contractName: string,
    functionName: string,
    senderAddress: string,
    ...args: string[]
  ): Promise<void> {
    const result = await this.cargoRunLocal([
      'execute',
      this.dbFilePath,
      contractName,
      functionName,
      senderAddress,
      ...args
    ]);
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Execute expression on contract failed with bad exit code ${
          result.exitCode
        }: ${result.stderr}`,
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

  async eval(contractName: string, evalStatement: string): Promise<string> {
    const result = await this.cargoRunLocal(
      ['eval', contractName, this.dbFilePath],
      {
        stdin: evalStatement
      }
    );
    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Eval expression on contract failed with bad exit code ${
          result.exitCode
        }: ${result.stderr}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    // Check and trim success prefix line.
    const successPrefix = result.stdout.match(
      /(Program executed successfully! Output: (\r\n|\r|\n))/
    );
    if (!successPrefix || successPrefix.length < 1) {
      throw new LocalExecutionError(
        `Eval expression on contract failed with bad output: ${result.stdout}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    // Get the output string with the prefix message and last EOL trimmed.
    const outputResult = result.stdout.substr(successPrefix[0].length);
    return outputResult;
  }

  async setBlockHeight(height: BigInt): Promise<void> {
    const result = await this.cargoRunLocal([
      'set_block_height',
      height.toString(),
      this.dbFilePath
    ]);

    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Set block height failed with bad exit code ${result.exitCode}: ${
          result.stderr
        }`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    if (result.stdout !== 'Simulated block height updated!') {
      throw new LocalExecutionError(
        `Set block height failed with bad output: ${result.stdout}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
  }

  async getBlockHeight(): Promise<BigInt> {
    const result = await this.cargoRunLocal([
      'get_block_height',
      this.dbFilePath
    ]);

    if (result.exitCode !== 0) {
      throw new LocalExecutionError(
        `Get block height failed with bad exit code ${result.exitCode}: ${
          result.stderr
        }`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    // Check and trim success prefix line.
    const successPrefix = result.stdout.match(
      /(Simulated block height: (\r\n|\r|\n))/
    );
    if (!successPrefix || successPrefix.length < 1) {
      throw new LocalExecutionError(
        `Get block height failed with bad output: ${result.stdout}`,
        result.exitCode,
        result.stdout,
        result.stderr
      );
    }
    // Get the output string with the prefix message and last EOL trimmed.
    const outputResult = result.stdout.substr(successPrefix[0].length);
    const heightInt = BigInt(outputResult);
    return heightInt;
  }

  async close(): Promise<void> {
    for (const closeAction of this.closeActions) {
      await closeAction();
    }
  }
}
