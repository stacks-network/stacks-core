import path from 'path';
import os from 'os';
import fs from 'fs';
import fsExtra from 'fs-extra';
import { assert } from 'chai';
import {
  LocalExecutionError,
  CargoLocalNodeExecutor,
  DeployedContract,
  LocalNodeExecutor
} from '../localNodeExec';

describe('sample contracts', () => {
  let tempDataDir: string;
  let dbFilePath: string;
  let contractsDir: string;
  let localNode: LocalNodeExecutor;

  let tokensContract: DeployedContract;
  let namesContract: DeployedContract;

  const DEMO_ADDRESS = 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR';

  before(async () => {
    tempDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'blockstack-local-'));
    dbFilePath = path.join(tempDataDir, 'db');
    contractsDir = path.join(__dirname, 'contracts');
    localNode = await CargoLocalNodeExecutor.create(dbFilePath);
  });

  it('check names contract fails', async () => {
    const namesContractFile = path.join(contractsDir, 'names.scm');
    try {
      await localNode.checkContract(namesContractFile);
      throw new Error('should have failed check');
    } catch (error) {
      if (error instanceof LocalExecutionError) {
        assert.equal(error.code, 1);
        assert.equal(
          error.errorOutput,
          'Type check error.\nNoSuchContract("tokens")\nNear:\n( contract-call! tokens token-transfer burn-address name-price )'
        );
      } else {
        throw error;
      }
    }
  });

  it('deploy tokens contract', async () => {
    const tokensContractFile = path.join(contractsDir, 'tokens.scm');
    tokensContract = await localNode.deployContract(
      'tokens',
      tokensContractFile
    );
  });

  it('check names contract succeeds', async () => {
    const namesContractFile = path.join(contractsDir, 'names.scm');
    await localNode.checkContract(namesContractFile);
  });

  it('deploy names contract', async () => {
    const namesContractFile = path.join(contractsDir, 'names.scm');
    namesContract = await localNode.deployContract('names', namesContractFile);
  });

  it('execute token mint', async () => {
    await tokensContract.execute('mint!', DEMO_ADDRESS, '100000');
  });

  it('get token balance', async () => {
    const tokenBalance = await tokensContract.eval(
      `(get-balance '${DEMO_ADDRESS})`
    );
    assert.equal(tokenBalance, '110000');
  });

  it('preorder name', async () => {
    const nameHash = await namesContract.eval('(hash160 (xor 10 8888))');
    assert.equal(nameHash, '0xb572fb1ce2e9665f1efd0994fe077b50c3a48fde');

    await namesContract.execute('preorder', DEMO_ADDRESS, nameHash, '1000');
  });

  it('balance reduced after name preorder', async () => {
    const balanceResult = await tokensContract.eval(
      `(get-balance '${DEMO_ADDRESS})`
    );
    assert.equal(balanceResult, '109000');
  });

  it('register name', async () => {
    await namesContract.execute(
      'register',
      DEMO_ADDRESS,
      `'${DEMO_ADDRESS}`,
      '10',
      '8888'
    );
  });

  it('get owner address for name', async () => {
    const nameOwner = await namesContract.eval(
      '(get owner (fetch-entry name-map (tuple (name 10))))'
    );
    assert.equal(nameOwner, "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
  });

  after(() => {
    // Cleanup temp data dir.
    fsExtra.removeSync(tempDataDir);
  });
});
