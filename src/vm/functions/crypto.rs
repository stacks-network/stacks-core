use vm::errors::{Error, CheckErrors, RuntimeErrorType, ShortReturnType, InterpreterResult as Result, check_argument_count, check_arguments_at_least};
use vm::types::{BUFF_32, BUFF_33, BUFF_65, BuffData, Value, SequenceData, CharType, PrincipalData, ResponseData, TypeSignature};
use vm::callables::{CallableType, NativeHandle};
use vm::representations::{SymbolicExpression, SymbolicExpressionType, ClarityName};
use vm::representations::SymbolicExpressionType::{List, Atom};
use vm::{LocalContext, Environment, eval};
use vm::costs::{cost_functions, MemoryConsumer, CostTracker, constants as cost_constants};
use util::hash;

use util::secp256k1::{Secp256k1PublicKey, secp256k1_recover, secp256k1_verify};

use chainstate::stacks::{C32_ADDRESS_VERSION_TESTNET_SINGLESIG, StacksAddress};
use address::AddressHashMode;

macro_rules! native_hash_func {
    ($name:ident, $module:ty) => {
        pub fn $name(input: Value) -> Result<Value> {
            let bytes = match input {
                Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
                Value::UInt(value) => Ok(value.to_le_bytes().to_vec()),
                Value::Sequence(SequenceData::Buffer(value)) => Ok(value.data),
                _ => Err(CheckErrors::UnionTypeValueError(vec![TypeSignature::IntType, TypeSignature::UIntType, TypeSignature::max_buffer()], input))
            }?;
            let hash = <$module>::from_data(&bytes);
            Value::buff_from(hash.as_bytes().to_vec())
        }
    }
}

native_hash_func!(native_hash160, hash::Hash160);
native_hash_func!(native_sha256, hash::Sha256Sum);
native_hash_func!(native_sha512, hash::Sha512Sum);
native_hash_func!(native_sha512trunc256, hash::Sha512Trunc256Sum);
native_hash_func!(native_keccak256, hash::Keccak256Hash);

pub fn special_principal_of(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    // (principal-of? (..))
    // arg0 => (buff 33)
    check_argument_count(1, args)?;

    runtime_cost!(cost_functions::PRINCIPAL_OF, env, 0)?;

    let param0 = eval(&args[0], env, context)?;
    let pub_key = match param0 {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => {
            if data.len() != 33 {
                return Err(CheckErrors::TypeValueError(BUFF_33, param0).into())
            }
            data
        },
        _ => return Err(CheckErrors::TypeValueError(BUFF_33, param0).into())
    };

    if let Ok(pub_key) = Secp256k1PublicKey::from_slice(&pub_key) {
    	let addr = StacksAddress::from_public_keys(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, &AddressHashMode::SerializeP2PKH, 1, &vec![pub_key]).unwrap();
    	let principal = addr.to_account_principal();
    	return Ok(Value::okay(Value::Principal(principal)).unwrap())
    } else {
    	return Ok(Value::err_uint(1))
    }
}

pub fn special_secp256k1_recover(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    // (secp256k1-recover? (..))
    // arg0 => (buff 32), arg1 => (buff 65)
    check_argument_count(2, args)?;

    runtime_cost!(cost_functions::SECP256K1RECOVER, env, 0)?;

    let param0 = eval(&args[0], env, context)?;
    let message = match param0 {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => {
            if data.len() != 32 {
                return Err(CheckErrors::TypeValueError(BUFF_32, param0).into())
            }
            data
        },
        _ => return Err(CheckErrors::TypeValueError(BUFF_32, param0).into())
    };

    let param1 = eval(&args[1], env, context)?;
    let signature = match param1 {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => {
        	if data.len() > 65 {
        	    return Err(CheckErrors::TypeValueError(BUFF_65, param1).into())
        	}
        	if data.len() < 65 || data[64] > 3 {
        	    return Ok(Value::err_uint(2))
        	}
            data
        },
        _ => return Err(CheckErrors::TypeValueError(BUFF_65, param1).into())
    };

    match secp256k1_recover(&message, &signature).map_err(|_| CheckErrors::InvalidSecp65k1Signature) {
        Ok(pubkey) => {
            return Ok(Value::okay(Value::buff_from(pubkey.to_vec()).unwrap()).unwrap())
        },
        _ => return Ok(Value::err_uint(1))
    };
}

pub fn special_secp256k1_verify(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    // (secp256k1-verify (..))
    // arg0 => (buff 32), arg1 => (buff 65), arg2 => (buff 33)
    check_argument_count(3, args)?;

    runtime_cost!(cost_functions::SECP256K1VERIFY, env, 0)?;

    let param0 = eval(&args[0], env, context)?;
    let message = match param0 {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => {
            if data.len() != 32 {
                return Err(CheckErrors::TypeValueError(BUFF_32, param0).into())
            }
            data
        },
        _ => return Err(CheckErrors::TypeValueError(BUFF_32, param0).into())
    };

    let param1 = eval(&args[1], env, context)?;
    let signature = match param1 {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => {
            if data.len() > 65 {
                return Err(CheckErrors::TypeValueError(BUFF_65, param1).into())
            }
            if data.len() < 64 {
                return Ok(Value::Bool(false))
            }
            if data.len() == 65 && data[64] > 3 {
                return Ok(Value::Bool(false))
            }
            data
        },
        _ => return Err(CheckErrors::TypeValueError(BUFF_65, param1).into())
    };

    let param2 = eval(&args[2], env, context)?;
    let pubkey = match param2 {
        Value::Sequence(SequenceData::Buffer(BuffData { ref data })) => {
            if data.len() != 33 {
                return Err(CheckErrors::TypeValueError(BUFF_33, param2).into())
            }
            data
        },
        _ => return Err(CheckErrors::TypeValueError(BUFF_33, param2).into())
    };

    Ok(Value::Bool(secp256k1_verify(&message, &signature, &pubkey).is_ok()))
}
