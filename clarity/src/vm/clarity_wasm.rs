use std::{borrow::BorrowMut, collections::HashMap};

use crate::vm::{
    analysis::ContractAnalysis,
    ast::ContractAST,
    contexts::GlobalContext,
    errors::{Error, WasmError},
    types::{BufferLength, SequenceSubtype, StringSubtype, TypeSignature},
    ClarityName, ContractContext, Value,
};
use wasmtime::{AsContextMut, Caller, Engine, Linker, Module, Store, Trap, Val};

use super::{
    analysis::CheckErrors, contracts::Contract, costs::CostTracker, errors::RuntimeErrorType,
};

pub struct ClarityWasmContext<'a, 'b, 'hooks> {
    /// The global context in which to execute.
    pub global_context: &'b mut GlobalContext<'a, 'hooks>,
    /// Context for this contract. This will be filled in when running the
    /// top-level expressions, then used when calling functions.
    pub contract_context: &'b mut ContractContext,
    /// Contract analysis data, used for typing information
    pub contract_analysis: &'b ContractAnalysis,
    /// Map an identifier from a contract to an integer id for simple access
    pub identifier_map: HashMap<i32, String>,
}

impl<'a, 'b, 'hooks> ClarityWasmContext<'a, 'b, 'hooks> {
    pub fn new(
        global_context: &'b mut GlobalContext<'a, 'hooks>,
        contract_context: &'b mut ContractContext,
        contract_analysis: &'b ContractAnalysis,
    ) -> Self {
        ClarityWasmContext {
            global_context,
            contract_context,
            contract_analysis,
            identifier_map: HashMap::new(),
        }
    }
}

pub fn initialize_contract(
    global_context: &mut GlobalContext,
    contract_context: &mut ContractContext,
    contract_analysis: &ContractAnalysis,
) -> Result<Option<Value>, Error> {
    let mut context = ClarityWasmContext::new(global_context, contract_context, contract_analysis);
    let engine = Engine::default();
    let module = context.contract_context.with_wasm_module(|wasm_module| {
        Module::from_binary(&engine, wasm_module)
            .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))
    })?;
    let mut store = Store::new(&engine, context);
    let mut linker = Linker::new(&engine);

    // Link in the host interface functions.
    link_define_variable_fn(&mut linker);
    link_get_variable_fn(&mut linker);
    link_set_variable_fn(&mut linker);
    link_log(&mut linker);

    let instance = linker.instantiate(store.as_context_mut(), &module).unwrap();

    // Call the `.top-level` function, which contains all top-level expressions
    // from the contract.
    let func = instance
        .get_func(store.as_context_mut(), ".top-level")
        .expect(".top-level function was not found in the generated WASM binary.");
    let mut results = [];

    func.call(store.as_context_mut(), &[], &mut results)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e)))?;

    Ok(None)
}

pub fn call_function(
    contract: &Contract,
    global_context: &mut GlobalContext,
    contract_context: &mut ContractContext,
    contract_analysis: &ContractAnalysis,
    function_name: &str,
    args: &[Value],
) -> Result<Option<Value>, Error> {
    let mut context = ClarityWasmContext::new(global_context, contract_context, contract_analysis);
    let engine = Engine::default();
    let module = context.contract_context.with_wasm_module(|wasm_module| {
        Module::from_binary(&engine, wasm_module)
            .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))
    })?;
    let mut store = Store::new(&engine, context);
    let mut linker = Linker::new(&engine);

    // Link in the host interface functions.
    link_define_variable_fn(&mut linker);
    link_get_variable_fn(&mut linker);
    link_set_variable_fn(&mut linker);
    link_log(&mut linker);

    let instance = linker.instantiate(store.as_context_mut(), &module).unwrap();

    // Call the specified function
    let func = instance
        .get_func(store.as_context_mut(), function_name)
        .ok_or(CheckErrors::UndefinedFunction(function_name.to_string()))?;

    // Convert the args into wasmtime values

    // Call the function

    Ok(None)
}

fn link_define_variable_fn(linker: &mut Linker<ClarityWasmContext>) {
    linker
        .func_wrap(
            "clarity",
            "define_variable",
            |mut caller: Caller<'_, ClarityWasmContext>,
             identifier: i32,
             name_offset: i32,
             name_length: i32,
             value_offset: i32,
             value_length: i32| {
                // TODO: Include this cost
                // runtime_cost(ClarityCostFunction::CreateVar, global_context, value_type.size())?;

                // Read the variable name string from the memory
                let name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;

                // Retrieve the type of this variable
                let value_type = caller
                    .data()
                    .contract_analysis
                    .get_persisted_variable_type(name.as_str())
                    .ok_or(Error::Unchecked(CheckErrors::DefineVariableBadSignature))?
                    .clone();

                let contract = caller.data().contract_context.contract_identifier.clone();

                // Read the initial value from the memory
                let value = read_from_wasm(&mut caller, &value_type, value_offset, value_length)?;

                caller
                    .data_mut()
                    .contract_context
                    .persisted_names
                    .insert(ClarityName::try_from(name.clone()).expect("name should be valid"));

                caller
                    .data_mut()
                    .global_context
                    .add_memory(
                        value_type
                            .type_size()
                            .expect("type size should be realizable")
                            as u64,
                    )
                    .map_err(|e| Error::from(e))?;

                caller
                    .data_mut()
                    .global_context
                    .add_memory(value.size() as u64)
                    .map_err(|e| Error::from(e))?;

                // Store the mapping of variable name to identifier
                caller
                    .data_mut()
                    .identifier_map
                    .insert(identifier, name.clone());

                // Create the variable in the global context
                let data_types = caller.data_mut().global_context.database.create_variable(
                    &contract,
                    name.as_str(),
                    value_type,
                );

                // Store the variable in the global context
                caller.data_mut().global_context.database.set_variable(
                    &contract,
                    name.as_str(),
                    value,
                    &data_types,
                )?;

                // Save the metadata for this variable in the contract context
                caller
                    .data_mut()
                    .contract_context
                    .meta_data_var
                    .insert(ClarityName::from(name.as_str()), data_types);

                Ok(())
            },
        )
        .unwrap();
}

fn link_get_variable_fn(linker: &mut Linker<ClarityWasmContext>) {
    linker
        .func_wrap(
            "clarity",
            "get_variable",
            |mut caller: Caller<'_, ClarityWasmContext>,
             identifier: i32,
             return_offset: i32,
             return_length: i32| {
                // Retrieve the variable name for this identifier
                let var_name = caller
                    .data()
                    .identifier_map
                    .get(&identifier)
                    .ok_or(Error::Wasm(WasmError::UnableToRetrieveIdentifier(
                        identifier,
                    )))?
                    .clone();

                let contract = caller.data().contract_context.contract_identifier.clone();

                // Retrieve the metadata for this variable
                let data_types = caller
                    .data()
                    .contract_context
                    .meta_data_var
                    .get(var_name.as_str())
                    .ok_or(CheckErrors::NoSuchDataVariable(var_name.to_string()))?
                    .clone();

                let result = caller
                    .data_mut()
                    .global_context
                    .database
                    .lookup_variable_with_size(&contract, var_name.as_str(), &data_types);

                let result_size = match &result {
                    Ok(data) => data.serialized_byte_len,
                    Err(_e) => data_types.value_type.size() as u64,
                };

                // TODO: Include this cost
                // runtime_cost(ClarityCostFunction::FetchVar, env, result_size)?;

                let value = result.map(|data| data.value)?;

                write_to_wasm(
                    &mut caller,
                    &data_types.value_type,
                    return_offset,
                    return_length,
                    value,
                )?;

                Ok(())
            },
        )
        .unwrap();
}

fn link_set_variable_fn(linker: &mut Linker<ClarityWasmContext>) {
    linker
        .func_wrap(
            "clarity",
            "set_variable",
            |mut caller: Caller<'_, ClarityWasmContext>,
             identifier: i32,
             value_offset: i32,
             value_length: i32| {
                let var_name = caller
                    .data()
                    .identifier_map
                    .get(&identifier)
                    .ok_or(Error::Wasm(WasmError::UnableToRetrieveIdentifier(
                        identifier,
                    )))?
                    .clone();

                let contract = caller.data().contract_context.contract_identifier.clone();

                let data_types = caller
                    .data()
                    .contract_context
                    .meta_data_var
                    .get(&ClarityName::from(var_name.as_str()))
                    .ok_or(Error::Unchecked(CheckErrors::NoSuchDataVariable(
                        var_name.to_string(),
                    )))?
                    .clone();

                // TODO: Include this cost
                // runtime_cost(
                //     ClarityCostFunction::SetVar,
                //     env,
                //     data_types.value_type.size(),
                // )?;

                // Read in the value from the Wasm memory
                let value = read_from_wasm(
                    &mut caller,
                    &data_types.value_type,
                    value_offset,
                    value_length,
                )?;

                // TODO: Include this cost
                // env.add_memory(value.get_memory_use())?;

                // Store the variable in the global context
                caller
                    .data_mut()
                    .global_context
                    .database
                    .set_variable(&contract, var_name.as_str(), value, &data_types)
                    .map_err(|e| Error::from(e))?;

                Ok(())
            },
        )
        .unwrap();
}

fn link_log(linker: &mut Linker<ClarityWasmContext>) {
    linker
        .func_wrap(
            "clarity",
            "log",
            |_: Caller<'_, ClarityWasmContext>, param: i64| {
                println!("log: {param}");
            },
        )
        .unwrap();
}

/// Read an identifier (string) from the WASM memory at `offset` with `length`.
fn read_identifier_from_wasm(
    caller: &mut Caller<'_, ClarityWasmContext>,
    offset: i32,
    length: i32,
) -> Result<String, Error> {
    // Get the memory from the caller
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

    let mut buffer: Vec<u8> = vec![0; length as usize];
    memory
        .read(caller, offset as usize, &mut buffer)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
    String::from_utf8(buffer).map_err(|e| Error::Wasm(WasmError::UnableToReadIdentifier(e)))
}

/// Read a value from the WASM memory at `offset` with `length` given the provided
/// Clarity `TypeSignature`.
fn read_from_wasm(
    caller: &mut Caller<'_, ClarityWasmContext>,
    ty: &TypeSignature,
    offset: i32,
    length: i32,
) -> Result<Value, Error> {
    // Get the memory from the caller
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

    match ty {
        TypeSignature::UIntType => {
            assert!(
                length == 16,
                "expected uint length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            memory
                .read(caller.borrow_mut(), offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let high = u64::from_le_bytes(buffer) as u128;
            memory
                .read(caller.borrow_mut(), (offset + 8) as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let low = u64::from_le_bytes(buffer) as u128;
            Ok(Value::UInt((high << 64) | low))
        }
        TypeSignature::IntType => {
            assert!(
                length == 16,
                "expected int length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            memory
                .read(caller.borrow_mut(), offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let high = u64::from_le_bytes(buffer) as u128;
            memory
                .read(caller.borrow_mut(), (offset + 8) as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let low = u64::from_le_bytes(buffer) as u128;
            Ok(Value::Int(((high << 64) | low) as i128))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
            type_length,
        ))) => {
            assert!(
                type_length
                    >= &BufferLength::try_from(length as u32).expect("invalid buffer length"),
                "expected string length to be less than the type length"
            );
            let mut buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(caller, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            Value::string_ascii_from_bytes(buffer)
        }
        _ => panic!("unsupported type"),
    }
}

/// Write a value to the Wasm memory at `offset` with `length` given the
/// provided Clarity `TypeSignature`.'
fn write_to_wasm(
    caller: &mut Caller<'_, ClarityWasmContext>,
    ty: &TypeSignature,
    offset: i32,
    length: i32,
    value: Value,
) -> Result<(), Error> {
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

    match ty {
        TypeSignature::IntType => {
            assert!(
                length == 16,
                "expected int length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            let i = value.expect_i128();
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            buffer.copy_from_slice(&high.to_le_bytes());
            memory
                .write(caller.borrow_mut(), offset as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            buffer.copy_from_slice(&low.to_le_bytes());
            memory
                .write(caller.borrow_mut(), (offset + 8) as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
        }
        _ => panic!("unsupported type"),
    };
    Ok(())
}

/// Reads an individual value from the Wasm memory buffer and translates it
/// into a Clarity `Value`.
fn read_value_from_memory(
    type_sig: &TypeSignature,
    index: usize,
    buffer: &[Val],
) -> (Value, usize) {
    match type_sig {
        TypeSignature::IntType => {
            let upper = buffer[index].unwrap_i64();
            let lower = buffer[index + 1].unwrap_i64();
            (Value::Int(((upper as i128) << 64) | lower as i128), 2)
        }
        TypeSignature::UIntType => {
            let upper = buffer[index].unwrap_i64();
            let lower = buffer[index + 1].unwrap_i64();
            (Value::UInt(((upper as u128) << 64) | lower as u128), 2)
        }
        TypeSignature::BoolType => (Value::Bool(buffer[index].unwrap_i32() != 0), 1),
        TypeSignature::OptionalType(optional) => {
            let (value, increment) = read_value_from_memory(optional, index + 1, buffer);
            (
                if buffer[index].unwrap_i32() == 1 {
                    Value::some(value).unwrap()
                } else {
                    Value::none()
                },
                increment + 1,
            )
        }
        TypeSignature::ResponseType(response) => {
            let (ok, increment_ok) = read_value_from_memory(&response.0, index + 1, buffer);
            let (err, increment_err) =
                read_value_from_memory(&response.1, index + 1 + increment_ok, buffer);
            (
                if buffer[index].unwrap_i32() == 1 {
                    Value::okay(ok).unwrap()
                } else {
                    Value::error(err).unwrap()
                },
                index + 1 + increment_ok + increment_err,
            )
        }
        // A `NoType` will be a dummy value that should not be used.
        TypeSignature::NoType => (Value::none(), 1),
        _ => panic!("WASM value type not implemented: {:?}", type_sig),
    }
}

fn clarity_to_wasm_value(type_sig: &TypeSignature, value: &Value) -> Result<Vec<Val>, Error> {
    match type_sig {
        TypeSignature::IntType => {
            let i = if let Value::Int(inner) = value {
                inner
            } else {
                return Err(Error::Unchecked(CheckErrors::TypeValueError(
                    type_sig.clone(),
                    value.clone(),
                )));
            };
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            Ok(vec![Val::I64(high as i64), Val::I64(low as i64)])
        }
        TypeSignature::UIntType => {
            let i = if let Value::UInt(inner) = value {
                inner
            } else {
                return Err(Error::Unchecked(CheckErrors::TypeValueError(
                    type_sig.clone(),
                    value.clone(),
                )));
            };
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            Ok(vec![Val::I64(high as i64), Val::I64(low as i64)])
        }
        TypeSignature::BoolType => {
            let v = if let Value::Bool(inner) = value {
                inner
            } else {
                return Err(Error::Unchecked(CheckErrors::TypeValueError(
                    type_sig.clone(),
                    value.clone(),
                )));
            };
            Ok(vec![Val::I32(if *v { 1 } else { 0 })])
        }
        TypeSignature::OptionalType(optional) => {
            let o = if let Value::Optional(inner) = value {
                inner
            } else {
                return Err(Error::Unchecked(CheckErrors::TypeValueError(
                    type_sig.clone(),
                    value.clone(),
                )));
            };
            let mut result = vec![Val::I32(if o.data.is_some() { 1 } else { 0 })];
            result.extend(clarity_to_wasm_value(
                optional,
                o.data
                    .as_ref()
                    .map_or(&Value::none(), |boxed_value| &boxed_value),
            )?);
            Ok(result)
        }
        TypeSignature::ResponseType(response) => {
            let r = if let Value::Response(inner) = value {
                inner
            } else {
                return Err(Error::Unchecked(CheckErrors::TypeValueError(
                    type_sig.clone(),
                    value.clone(),
                )));
            };
            let mut result = vec![Val::I32(if r.committed { 1 } else { 0 })];
            result.extend(if r.committed {
                clarity_to_wasm_value(&response.0, &r.data)?
            } else {
                vec![Val::I32(0)]
            });
            result.extend(if !r.committed {
                clarity_to_wasm_value(&response.1, &r.data)?
            } else {
                vec![Val::I32(0)]
            });

            Ok(result)
        }
        // A `NoType` will be a dummy value that should not be used.
        TypeSignature::NoType => Ok(vec![]),
        _ => unimplemented!("Value type not implemented: {:?}", type_sig),
    }
}
