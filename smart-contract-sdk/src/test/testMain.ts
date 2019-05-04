import path from 'path';
import os from 'os';
import fs from 'fs';
import fsExtra from 'fs-extra';
import { assert } from 'chai';
import * as sdk from '../localNodeExec';

describe('main', () => {
  let tempDataDir: string;
  let dbFilePath: string;
  let contractsDir: string;

  const DEMO_ADDRESS = 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR';

  before(() => {
    tempDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'blockstack-local-'));
    dbFilePath = path.join(tempDataDir, 'db');
    contractsDir = path.join(__dirname, 'contracts');
  });

  it('cargo build', async () => {
    const result = await sdk.cargoBuild();
    assert.include(
      result.stderr,
      'Finished',
      'Cargo build should have finished'
    );
    assert.equal(result.exitCode, 0, 'Cargo build should have OK exit code');
  });

  it('init db', async () => {
    const result = await sdk.cargoRunLocal(['initialize', dbFilePath]);
    assert.equal(result.stdout, 'Database created.');
    assert.equal(result.exitCode, 0);
  });

  it('check names contract fails', async () => {
    const namesContractFile = path.join(contractsDir, 'names.scm');
    const result = await sdk.cargoRunLocal([
      'check',
      namesContractFile,
      dbFilePath
    ]);
    assert.equal(result.stdout, '', 'Should have empty any stdout');
    assert.equal(result.exitCode, 1, 'Should exit code 1');
  });

  it('deploy tokens contract', async () => {
    const tokensContractFile = path.join(contractsDir, 'tokens.scm');
    const result = await sdk.cargoRunLocal([
      'launch',
      'tokens',
      tokensContractFile,
      dbFilePath
    ]);
    assert.equal(result.stdout, 'Contract initialized!');
    assert.equal(result.exitCode, 0);
  });

  it('check names contract succeeds', async () => {
    const namesContractFile = path.join(contractsDir, 'names.scm');
    const result = await sdk.cargoRunLocal([
      'check',
      namesContractFile,
      dbFilePath
    ]);
    assert.equal(result.stdout, '', 'Should have empty any stdout');
    assert.equal(result.exitCode, 0, 'Should successful');
  });

  it('deploy names contract', async () => {
    const namesContractFile = path.join(contractsDir, 'names.scm');
    const result = await sdk.cargoRunLocal([
      'launch',
      'names',
      namesContractFile,
      dbFilePath
    ]);
    assert.equal(result.stdout, 'Contract initialized!');
    assert.equal(result.exitCode, 0);
  });

  it('execute token mint', async () => {
    const result = await sdk.cargoRunLocal([
      'execute',
      dbFilePath,
      'tokens',
      'mint!',
      DEMO_ADDRESS,
      '100000'
    ]);
    assert.equal(result.stdout, 'Transaction executed and committed.');
    assert.equal(result.exitCode, 0);
  });

  it('get token balance', async () => {
    const tokenBalance = await sdk.cargoEvalStatement(
      'tokens',
      `(get-balance '${DEMO_ADDRESS})`,
      dbFilePath
    );
    assert.equal(tokenBalance, '110000');
  });

  it('preorder name', async () => {
    const nameHash = await sdk.cargoEvalStatement(
      'names',
      '(hash160 (xor 10 8888))',
      dbFilePath
    );
    assert.equal(nameHash, '0xb572fb1ce2e9665f1efd0994fe077b50c3a48fde');

    const executeResult = await sdk.cargoRunLocal([
      'execute',
      dbFilePath,
      'names',
      'preorder',
      DEMO_ADDRESS,
      nameHash,
      '1000'
    ]);
    assert.equal(executeResult.stdout, 'Transaction executed and committed.');
    assert.equal(executeResult.exitCode, 0);
  });

  it('balance reduced after name preorder', async () => {
    const balanceResult = await sdk.cargoEvalStatement(
      'tokens',
      `(get-balance '${DEMO_ADDRESS})`,
      dbFilePath
    );
    assert.equal(balanceResult, '109000');
  });

  it('register name', async () => {
    const result = await sdk.cargoRunLocal([
      'execute',
      dbFilePath,
      'names',
      'register',
      DEMO_ADDRESS,
      `'${DEMO_ADDRESS}`,
      '10',
      '8888'
    ]);
    assert.equal(result.stdout, 'Transaction executed and committed.');
    assert.equal(result.exitCode, 0);
  });

  it('get owner address for name', async () => {
    const nameOwner = await sdk.cargoEvalStatement(
      'names',
      '(get owner (fetch-entry name-map (tuple (name 10))))',
      dbFilePath
    );
    assert.equal(nameOwner, "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
  });

  after(() => {
    // Cleanup temp data dir.
    fsExtra.removeSync(tempDataDir);
  });
});
