import path from 'path';
import { assert } from 'chai';
import { CargoLocalNodeExecutor, LocalNodeExecutor } from '../localNodeExec';
import {
  FunctionArgTypes,
  FunctionReturnType,
  ContractTypes
} from '../ContractTypes';

describe('sample contracts', () => {
  let contractsDir: string;
  let localNode: LocalNodeExecutor;
  let contractTypes: ContractTypes;

  before(async () => {
    contractsDir = path.join(__dirname, 'contracts');
    localNode = await CargoLocalNodeExecutor.createEphemeral();

    const tokensContractFile = path.join(contractsDir, 'tokens.scm');
    await localNode.launchContract('tokens', tokensContractFile);

    const namesContractFile = path.join(contractsDir, 'names.scm');
    const checkResult = await localNode.checkContract(namesContractFile);
    contractTypes = checkResult.contractTypes;
    assert.isTrue(checkResult.isValid, checkResult.message);
  });

  it('check private function types', async () => {
    const priceFuncSig = contractTypes.private_function_types['price-function'];
    assert.isOk(priceFuncSig.Fixed);
    const priceFuncArgs = priceFuncSig.Fixed[FunctionArgTypes];
    assert.equal(priceFuncArgs[0].atomic_type, 'IntType');
    const priceFuncReturnType = priceFuncSig.Fixed[FunctionReturnType];
    assert.equal(priceFuncReturnType.atomic_type, 'IntType');
  });

  it('check public function types', async () => {
    const preorderFuncSig = contractTypes.public_function_types['preorder'];
    assert.isOk(preorderFuncSig.Fixed);
    assert.deepEqual(preorderFuncSig.Fixed[FunctionArgTypes][0].atomic_type, {
      BufferType: 20
    });
    assert.equal(
      preorderFuncSig.Fixed[FunctionArgTypes][1].atomic_type,
      'IntType'
    );
    assert.equal(
      preorderFuncSig.Fixed[FunctionReturnType].atomic_type,
      'BoolType'
    );

    const registerFuncSig = contractTypes.public_function_types['register'];
    assert.isOk(registerFuncSig.Fixed);
    assert.equal(
      registerFuncSig.Fixed[FunctionArgTypes][0].atomic_type,
      'PrincipalType'
    );
    assert.equal(
      registerFuncSig.Fixed[FunctionArgTypes][1].atomic_type,
      'IntType'
    );
    assert.equal(
      registerFuncSig.Fixed[FunctionArgTypes][2].atomic_type,
      'IntType'
    );
    assert.equal(
      registerFuncSig.Fixed[FunctionReturnType].atomic_type,
      'BoolType'
    );
  });

  it('check variable types', async () => {
    const burnAddressVarType = contractTypes.variable_types['burn-address'];
    assert.equal(burnAddressVarType.atomic_type, 'PrincipalType');
  });

  it('check map types', async () => {
    const nameMap = contractTypes.map_types['name-map'];
    assert.deepEqual(nameMap[0].atomic_type, {
      TupleType: {
        type_map: {
          name: {
            atomic_type: 'IntType',
            list_dimensions: null
          }
        }
      }
    });
    assert.deepEqual(nameMap[1].atomic_type, {
      TupleType: {
        type_map: {
          owner: {
            atomic_type: 'PrincipalType',
            list_dimensions: null
          }
        }
      }
    });

    const preorderMap = contractTypes.map_types['preorder-map'];
    assert.deepEqual(preorderMap[0].atomic_type, {
      TupleType: {
        type_map: {
          'name-hash': {
            atomic_type: {
              BufferType: 20
            },
            list_dimensions: null
          }
        }
      }
    });
    assert.deepEqual(preorderMap[1].atomic_type, {
      TupleType: {
        type_map: {
          buyer: {
            atomic_type: 'PrincipalType',
            list_dimensions: null
          },
          paid: {
            atomic_type: 'IntType',
            list_dimensions: null
          }
        }
      }
    });
  });

  after(async () => {
    // Cleanup node.
    await localNode.close();
  });
});
