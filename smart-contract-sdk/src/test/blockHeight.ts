import path from 'path';
import { assert } from 'chai';
import {
  LocalExecutionError,
  CargoLocalNodeExecutor,
  LaunchedContract,
  LocalNodeExecutor
} from '../localNodeExec';

describe('block height testing', () => {
  let contractsDir: string;
  let localNode: LocalNodeExecutor;

  let blockHeightTestContract: LaunchedContract;

  const DEMO_ADDRESS = 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR';

  before(async () => {
    contractsDir = path.join(__dirname, 'contracts');
    localNode = await CargoLocalNodeExecutor.createEphemeral();
  });

  it('set local node block height', async () => {
    await localNode.setBlockHeight(BigInt('117'));
  });

  it('check block height contract', async () => {
    const blockHeightTestsContractFile = path.join(
      contractsDir,
      'block-height-test.scm'
    );
    const checkResult = await localNode.checkContract(
      blockHeightTestsContractFile
    );
    assert.isTrue(checkResult.isValid, checkResult.message);
  });

  it('launch block height contract', async () => {
    const blockHeightTestsContractFile = path.join(
      contractsDir,
      'block-height-test.scm'
    );
    blockHeightTestContract = await localNode.launchContract(
      'block-height-tests',
      blockHeightTestsContractFile
    );
  });

  it('get deployed block height', async () => {
    const deployHeight = await blockHeightTestContract.eval(
      '(get-height-info 123)'
    );
    assert.equal(deployHeight, '117');
    const heightAtDeployment = await blockHeightTestContract.eval(
      'height-at-deployment'
    );
    assert.equal(heightAtDeployment, '117');
  });

  it('increment block height', async () => {
    const currentHeightOutput = await blockHeightTestContract.eval(
      '(get-current-block-height)'
    );
    assert.equal(currentHeightOutput, '117');
    const newHeight = BigInt(currentHeightOutput) + BigInt(100);
    await localNode.setBlockHeight(newHeight);
    const getHeightCheck = await localNode.getBlockHeight();
    assert.equal(getHeightCheck, BigInt('217'));
    const newHeightOutput = await blockHeightTestContract.eval(
      '(get-current-block-height)'
    );
    assert.equal(newHeightOutput, '217');
  });

  after(async () => {
    // Cleanup node.
    await localNode.close();
  });
});
