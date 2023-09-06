use std::{
    borrow::BorrowMut,
    collections::HashMap,
    fs::File,
    io::{Read, Write},
};

use crate::vm::{
    analysis::ContractAnalysis,
    ast::ContractAST,
    contexts::GlobalContext,
    errors::{Error, WasmError},
    types::{
        BuffData, BufferLength, SequenceSubtype, StandardPrincipalData, StringSubtype,
        TypeSignature,
    },
    ClarityName, ContractContext, ContractName, Value,
};
use wasmtime::{AsContextMut, Caller, Engine, Linker, Memory, Module, Store, Trap, Val};

use super::{
    analysis::CheckErrors,
    callables::{DefineType, DefinedFunction},
    contracts::Contract,
    costs::CostTracker,
    database::{clarity_db::ValueResult, ClarityDatabase, DataVariableMetadata},
    errors::RuntimeErrorType,
    types::{
        CallableData, CharType, FixedFunction, FunctionType, OptionalData, PrincipalData,
        QualifiedContractIdentifier, SequenceData,
    },
    SymbolicExpression,
};

trait ClarityWasmContext {
    fn contract_identifier(&self) -> &QualifiedContractIdentifier;
    fn get_var_metadata(&self, name: &str) -> Option<&DataVariableMetadata>;
    fn lookup_variable_with_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult, Error>;
    fn set_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value: Value,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult, Error>;
}

/// The context used when making calls into the Wasm module.
pub struct ClarityWasmRunContext<'a, 'b> {
    /// The global context in which to execute.
    pub global_context: &'b mut GlobalContext<'a>,
    /// Context for this contract. This will be filled in when running the
    /// top-level expressions, then used when calling functions.
    pub contract_context: &'b mut ContractContext,
}

impl<'a, 'b> ClarityWasmRunContext<'a, 'b> {
    pub fn new(
        global_context: &'b mut GlobalContext<'a>,
        contract_context: &'b mut ContractContext,
    ) -> Self {
        ClarityWasmRunContext {
            global_context,
            contract_context,
        }
    }
}

impl ClarityWasmContext for ClarityWasmRunContext<'_, '_> {
    fn contract_identifier(&self) -> &QualifiedContractIdentifier {
        &self.contract_context.contract_identifier
    }

    fn get_var_metadata(&self, name: &str) -> Option<&DataVariableMetadata> {
        self.contract_context.meta_data_var.get(name)
    }

    fn lookup_variable_with_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult, Error> {
        self.global_context.database.lookup_variable_with_size(
            contract_identifier,
            variable_name,
            variable_descriptor,
        )
    }

    fn set_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value: Value,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult, Error> {
        self.global_context.database.set_variable(
            contract_identifier,
            variable_name,
            value,
            variable_descriptor,
        )
    }
}

/// The context used when initializing the Wasm module. It embeds the
/// `ClarityWasmRunContext`, but also includes the contract analysis data for
/// typing information.
pub struct ClarityWasmInitContext<'a, 'b> {
    pub run_context: ClarityWasmRunContext<'a, 'b>,
    /// Contract analysis data, used for typing information
    pub contract_analysis: &'b ContractAnalysis,
}

impl<'a, 'b> ClarityWasmInitContext<'a, 'b> {
    pub fn new(
        global_context: &'b mut GlobalContext<'a>,
        contract_context: &'b mut ContractContext,
        contract_analysis: &'b ContractAnalysis,
    ) -> Self {
        ClarityWasmInitContext {
            run_context: ClarityWasmRunContext {
                global_context,
                contract_context,
            },
            contract_analysis,
        }
    }
}

impl ClarityWasmContext for ClarityWasmInitContext<'_, '_> {
    fn contract_identifier(&self) -> &QualifiedContractIdentifier {
        &self.run_context.contract_context.contract_identifier
    }

    fn get_var_metadata(&self, name: &str) -> Option<&DataVariableMetadata> {
        self.run_context.contract_context.meta_data_var.get(name)
    }

    fn lookup_variable_with_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult, Error> {
        self.run_context
            .global_context
            .database
            .lookup_variable_with_size(contract_identifier, variable_name, variable_descriptor)
    }

    fn set_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value: Value,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult, Error> {
        self.run_context.global_context.database.set_variable(
            contract_identifier,
            variable_name,
            value,
            variable_descriptor,
        )
    }
}

/// Initialize a contract, executing all of the top-level expressions and
/// registering all of the definitions in the context.
pub fn initialize_contract(
    global_context: &mut GlobalContext,
    contract_context: &mut ContractContext,
    contract_analysis: &ContractAnalysis,
) -> Result<Option<Value>, Error> {
    let context = ClarityWasmInitContext::new(global_context, contract_context, contract_analysis);
    let engine = Engine::default();
    let module = context
        .run_context
        .contract_context
        .with_wasm_module(|wasm_module| {
            Module::from_binary(&engine, wasm_module)
                .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))
        })?;
    let mut store = Store::new(&engine, context);
    let mut linker = Linker::new(&engine);

    // Link in the host interface functions.
    link_define_function_fn(&mut linker)?;
    link_define_variable_fn(&mut linker)?;
    link_get_variable_fn(&mut linker)?;
    link_set_variable_fn(&mut linker)?;
    link_log(&mut linker)?;

    let instance = linker
        .instantiate(store.as_context_mut(), &module)
        .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))?;

    // Call the `.top-level` function, which contains all top-level expressions
    // from the contract.
    let func = instance
        .get_func(store.as_context_mut(), ".top-level")
        .ok_or(Error::Wasm(WasmError::TopLevelNotFound))?;
    let mut results = [];

    func.call(store.as_context_mut(), &[], &mut results)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e)))?;

    Ok(None)
}

/// Call a function in the contract.
pub fn call_function(
    global_context: &mut GlobalContext,
    contract_context: &mut ContractContext,
    function_name: &str,
    args: &[Value],
) -> Result<Value, Error> {
    let context = ClarityWasmRunContext::new(global_context, contract_context);
    let engine = Engine::default();
    let module = context.contract_context.with_wasm_module(|wasm_module| {
        Module::from_binary(&engine, wasm_module)
            .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))
    })?;
    let mut store = Store::new(&engine, context);
    let mut linker = Linker::new(&engine);

    // Link in the host interface functions.
    link_define_function_fn_error(&mut linker)?;
    link_define_variable_fn_error(&mut linker)?;
    link_get_variable_fn(&mut linker)?;
    link_set_variable_fn(&mut linker)?;
    link_log(&mut linker)?;

    let instance = linker
        .instantiate(store.as_context_mut(), &module)
        .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))?;

    // Call the specified function
    let func = instance
        .get_func(store.as_context_mut(), function_name)
        .ok_or(CheckErrors::UndefinedFunction(function_name.to_string()))?;

    // Access the global stack pointer from the instance
    let stack_pointer = instance
        .get_global(store.as_context_mut(), "stack-pointer")
        .ok_or(Error::Wasm(WasmError::StackPointerNotFound))?;
    let mut offset = stack_pointer
        .get(store.as_context_mut())
        .i32()
        .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;

    let memory = instance
        .get_memory(store.as_context_mut(), "memory")
        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

    // Convert the args into wasmtime values
    let mut wasm_args = vec![];
    for arg in args {
        let (arg_vec, new_offset) =
            pass_argument_to_wasm(memory, store.as_context_mut(), arg, offset)?;
        wasm_args.extend(arg_vec);
        offset = new_offset;
    }

    // Reserve stack space for the return value, if necessary.
    let return_type = store
        .data()
        .contract_context
        .functions
        .get(function_name)
        .ok_or(CheckErrors::UndefinedFunction(function_name.to_string()))?
        .get_return_type()
        .clone();
    let (mut results, offset) = reserve_space_for_return(&mut store, offset, &return_type)?;

    // Update the stack pointer after space is reserved for the arguments and
    // return values.
    stack_pointer
        .set(store.as_context_mut(), Val::I32(offset))
        .map_err(|e| Error::Wasm(WasmError::Runtime(e)))?;

    // Call the function
    func.call(store.as_context_mut(), &wasm_args, &mut results)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e)))?;

    // If the function returns a value, translate it into a Clarity `Value`
    wasm_to_clarity_value(
        &return_type,
        0,
        &results,
        memory,
        &mut store.as_context_mut(),
    )
    .map(|(val, _offset)| val)
    .and_then(|option_value| {
        option_value.ok_or_else(|| Error::Wasm(WasmError::ExpectedReturnValue))
    })
}

/// Link host interface function, `define_function`, into the Wasm module.
/// This function is called for all function definitions.
fn link_define_function_fn(linker: &mut Linker<ClarityWasmInitContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_function",
            |mut caller: Caller<'_, ClarityWasmInitContext>,
             kind: i32,
             name_offset: i32,
             name_length: i32| {
                // Read the variable name string from the memory
                let function_name =
                    read_identifier_from_wasm(&mut caller, name_offset, name_length)?;
                let function_cname = ClarityName::try_from(function_name.clone())?;

                // Retrieve the kind of function
                let (define_type, function_type) = match kind {
                    0 => (
                        DefineType::ReadOnly,
                        caller
                            .data()
                            .contract_analysis
                            .get_read_only_function_type(&function_name)
                            .ok_or(Error::Unchecked(CheckErrors::UnknownFunction(
                                function_name.clone(),
                            )))?,
                    ),
                    1 => (
                        DefineType::Public,
                        caller
                            .data()
                            .contract_analysis
                            .get_public_function_type(&function_name)
                            .ok_or(Error::Unchecked(CheckErrors::UnknownFunction(
                                function_name.clone(),
                            )))?,
                    ),
                    2 => (
                        DefineType::Private,
                        caller
                            .data()
                            .contract_analysis
                            .get_private_function(&function_name)
                            .ok_or(Error::Unchecked(CheckErrors::UnknownFunction(
                                function_name.clone(),
                            )))?,
                    ),
                    _ => Err(Error::Wasm(WasmError::InvalidFunctionKind(kind)))?,
                };

                let fixed_type = match function_type {
                    FunctionType::Fixed(fixed_type) => fixed_type,
                    _ => Err(Error::Unchecked(CheckErrors::DefineFunctionBadSignature))?,
                };

                let function = DefinedFunction::new(
                    fixed_type
                        .args
                        .iter()
                        .map(|arg| (arg.name.clone(), arg.signature.clone()))
                        .collect(),
                    // TODO: We don't actually need the body here, so we
                    // should be able to remove it. For now, this is a
                    // placeholder.
                    SymbolicExpression::literal_value(Value::Int(0)),
                    define_type,
                    &function_cname,
                    &caller
                        .data()
                        .run_context
                        .contract_context
                        .contract_identifier
                        .to_string(),
                    fixed_type.returns.clone(),
                );

                // Insert this function into the context
                caller
                    .data_mut()
                    .run_context
                    .contract_context
                    .functions
                    .insert(function_cname, function);

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_function".to_string(),
                e,
            ))
        })
}

/// When in run-mode (not initialize-mode), this should never be called.
fn link_define_function_fn_error<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "define_function",
            |mut _caller: Caller<'_, T>, _kind: i32, _name_offset: i32, _name_length: i32| {
                // FIXME: I don't understand why I have to write this like this
                // instead of just:
                //   Err(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))
                let _ = Err(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?;
                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_function".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `define_variable`, into the Wasm module.
/// This function is called for all variable definitions (`define-data-var`).
fn link_define_variable_fn(linker: &mut Linker<ClarityWasmInitContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_variable",
            |mut caller: Caller<'_, ClarityWasmInitContext>,
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

                let contract = caller
                    .data()
                    .run_context
                    .contract_context
                    .contract_identifier
                    .clone();

                // Read the initial value from the memory
                let value = read_from_wasm(&mut caller, &value_type, value_offset, value_length)?;

                caller
                    .data_mut()
                    .run_context
                    .contract_context
                    .persisted_names
                    .insert(ClarityName::try_from(name.clone())?);

                caller
                    .data_mut()
                    .run_context
                    .global_context
                    .add_memory(value_type.type_size()? as u64)
                    .map_err(|e| Error::from(e))?;

                caller
                    .data_mut()
                    .run_context
                    .global_context
                    .add_memory(value.size() as u64)
                    .map_err(|e| Error::from(e))?;

                // Create the variable in the global context
                let data_types = caller
                    .data_mut()
                    .run_context
                    .global_context
                    .database
                    .create_variable(&contract, name.as_str(), value_type);

                // Store the variable in the global context
                caller
                    .data_mut()
                    .run_context
                    .global_context
                    .database
                    .set_variable(&contract, name.as_str(), value, &data_types)?;

                // Save the metadata for this variable in the contract context
                caller
                    .data_mut()
                    .run_context
                    .contract_context
                    .meta_data_var
                    .insert(ClarityName::from(name.as_str()), data_types);

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_variable".to_string(),
                e,
            ))
        })
}

/// When in run-mode (not initialize-mode), this should never be called.
fn link_define_variable_fn_error<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "define_variable",
            |mut _caller: Caller<'_, T>,
             _name_offset: i32,
             _name_length: i32,
             _value_offset: i32,
             _value_length: i32| {
                // FIXME: I don't understand why I have to write this like this
                // instead of just:
                //   Err(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))
                let _ = Err(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?;
                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_variable".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `get_variable`, into the Wasm module.
/// This function is called for all variable lookups (`var-get`).
fn link_get_variable_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "get_variable",
            |mut caller: Caller<'_, T>,
             name_offset: i32,
             name_length: i32,
             return_offset: i32,
             return_length: i32| {
                // Retrieve the variable name for this identifier
                let var_name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;

                let contract = caller.data().contract_identifier().clone();

                // Retrieve the metadata for this variable
                let data_types = caller
                    .data()
                    .get_var_metadata(&var_name)
                    .ok_or(CheckErrors::NoSuchDataVariable(var_name.to_string()))?
                    .clone();

                let result = caller.data_mut().lookup_variable_with_size(
                    &contract,
                    var_name.as_str(),
                    &data_types,
                );

                let _result_size = match &result {
                    Ok(data) => data.serialized_byte_len,
                    Err(_e) => data_types.value_type.size() as u64,
                };

                // TODO: Include this cost
                // runtime_cost(ClarityCostFunction::FetchVar, env, result_size)?;

                let value = result.map(|data| data.value)?;

                // TODO: @Brice: why are we writing to memory in a get-function?
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
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "get_variable".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `set_variable`, into the Wasm module.
/// This function is called for all variable assignments (`var-set`).
fn link_set_variable_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "set_variable",
            |mut caller: Caller<'_, T>,
             name_offset: i32,
             name_length: i32,
             value_offset: i32,
             value_length: i32| {
                // Retrieve the variable name for this identifier
                let var_name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;

                let contract = caller.data().contract_identifier().clone();

                let data_types = caller
                    .data()
                    .get_var_metadata(&var_name)
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
                    .set_variable(&contract, var_name.as_str(), value, &data_types)
                    .map_err(|e| Error::from(e))?;

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "set_variable".to_string(),
                e,
            ))
        })
}

/// Link host-interface function, `log`, into the Wasm module.
/// This function is used for debugging the Wasm, and should not be called in
/// production.
fn link_log<T>(linker: &mut Linker<T>) -> Result<(), Error> {
    linker
        .func_wrap("clarity", "log", |_: Caller<'_, T>, param: i64| {
            println!("log: {param}");
        })
        .map(|_| ())
        .map_err(|e| Error::Wasm(WasmError::UnableToLinkHostFunction("log".to_string(), e)))
}

/// Read an identifier (string) from the WASM memory at `offset` with `length`.
fn read_identifier_from_wasm<T>(
    caller: &mut Caller<'_, T>,
    offset: i32,
    length: i32,
) -> Result<String, Error>
where
    T: ClarityWasmContext,
{
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
fn read_from_wasm<T>(
    caller: &mut Caller<'_, T>,
    ty: &TypeSignature,
    offset: i32,
    length: i32,
) -> Result<Value, Error>
where
    T: ClarityWasmContext,
{
    // Get the memory from the caller
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

    // Allocate a buffer of `length` size to read the memory into.
    let mut buffer = Vec::<u8>::with_capacity(length as usize);

    // Read the memory at `offset` into `buffer`.
    memory
        .read(caller.borrow_mut(), offset as usize, &mut buffer)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;

    // Deserialize the clarity value from the read memory.
    deserialize_clarity_value(buffer, ty)
}

fn value_as_i128(value: &Value) -> Result<i128, Error> {
    match value {
        Value::Int(n) => Ok(*n),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

fn value_as_u128(value: &Value) -> Result<u128, Error> {
    match value {
        Value::UInt(n) => Ok(*n),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

/// Write a value to the Wasm memory at `offset` with `length` given the
/// provided Clarity `TypeSignature`.'
// TODO: @Brice: Why do we need both TypeSignature and Value here? Should be able to simply use the Value?
// And why do we pass in length? That should rather be a return value?
fn write_to_wasm<T>(
    caller: &mut Caller<'_, T>,
    ty: &TypeSignature,
    offset: i32,
    length: i32,
    value: Value,
) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

    match ty {
        TypeSignature::IntType => {
            debug_assert!(
                length == 16,
                "expected int length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            let i = value_as_i128(&value)?;
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            buffer.copy_from_slice(&low.to_le_bytes());
            memory
                .write(caller.borrow_mut(), offset as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            buffer.copy_from_slice(&high.to_le_bytes());
            memory
                .write(caller.borrow_mut(), (offset + 8) as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
        }
        TypeSignature::UIntType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::SequenceType(_) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ResponseType(_) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::BoolType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::CallableType(_) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ListUnionType(_) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::NoType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::OptionalType(_) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::PrincipalType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TraitReferenceType(_) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TupleType(_) => todo!("type not yet implemented: {:?}", ty),
    };
    Ok(())
}

/// Deserializes a Clarity `Value` from the provided buffer using the given
/// `TypeSignature`. More documentation regarding how values are serialized
/// can be found in the `pass_argument_to_wasm` function.
fn deserialize_clarity_value(buffer: Vec<u8>, ty: &TypeSignature) -> Result<Value, Error> {
    let type_marker = buffer[0];
    let value = buffer[1..].to_vec();
    let length: usize = value.len();

    match ty {
        TypeSignature::UIntType => {
            debug_assert!(
                length == 16,
                "expected uint length to be 16 bytes, found {length}"
            );

            let low_bytes: [u8; 8] = value[0..7]
                .try_into()
                .map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))?;

            let high_bytes: [u8; 8] = value[8..15]
                .try_into()
                .map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))?;

            let low = u64::from_le_bytes(low_bytes) as u128;
            let high = u64::from_le_bytes(high_bytes) as u128;

            Ok(Value::UInt((high << 64) | low))
        }
        TypeSignature::IntType => {
            debug_assert!(
                length == 16,
                "expected int length to be 16 bytes, found {length}"
            );

            let low_bytes: [u8; 8] = value[0..7]
                .try_into()
                .map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))?;

            let high_bytes: [u8; 8] = value[8..15]
                .try_into()
                .map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))?;

            let low = u64::from_le_bytes(low_bytes) as u128;
            let high = u64::from_le_bytes(high_bytes) as u128;

            Ok(Value::Int(((high << 64) | low) as i128))
        }
        TypeSignature::BoolType => {
            debug_assert!(
                length as u32 == 1,
                "Expected buffer length to be 1 for bool, received {length}"
            );

            let val = value[0];

            debug_assert!(
                value[0] == 1 || value[0] == 0,
                "Expected boolean value to be 1 or 0, received {val}"
            );

            Ok(Value::Bool(if val == 1 { true } else { false }))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(subtype)) => {
            let type_length = match subtype {
                StringSubtype::ASCII(len) => u32::from(len),
                StringSubtype::UTF8(len) => u32::from(len),
            };

            debug_assert!(
                type_length >= length as u32,
                "Expected string length to be less than the type length"
            );

            match subtype {
                StringSubtype::ASCII(_) => Value::string_ascii_from_bytes(value),
                StringSubtype::UTF8(_) => Value::string_utf8_from_bytes(value),
            }
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(b)) => {
            debug_assert!(
                length as u32 == u32::from(b),
                "Expected buffer length to be {b} but received {length}."
            );

            Ok(Value::Sequence(SequenceData::Buffer(BuffData {
                data: value,
            })))
        }
        TypeSignature::ResponseType(r) => {
            // Read the first byte (indicator). 1/true = Ok, 0/false = Err.
            let result = if value[0] == 1 { true } else { false };
            // Grab the remainer of the buffer.
            let rest = &value[1..length - 1];

            if result {
                // If Ok, we will deserialize using the Ok `TypeSignature` (position 0 in the tuple).
                deserialize_clarity_value(rest.to_vec(), &r.0)
            } else {
                // Otherwise if Err, we deserialize using the Err `TypeSignature` (position 1 in the tuple).
                deserialize_clarity_value(rest.to_vec(), &r.1)
            }
        }
        TypeSignature::OptionalType(o) => {
            // Read the first byte (indicator). 1/true = Some, 0/false = None.
            let some = if value[0] == 1 { true } else { false };

            if some {
                // If Some, grab the remainder of the buffer and deserialize using the Option `TypeSignature`.
                // Note that there are no additional bytes if the value is None, so we only do this if we
                // have a Some indicator above.
                let rest = &value[1..length - 1];
                let val = deserialize_clarity_value(rest.to_vec(), &o)?;
                Ok(Value::Optional(OptionalData {
                    data: Some(Box::new(val)),
                }))
            } else {
                // The indicator signals a None value, so we simply return None.
                Ok(Value::Optional(OptionalData { data: None }))
            }
        }
        TypeSignature::PrincipalType => {
            let type_indicator = value[0];

            debug_assert!(
                [1, 2].contains(&type_indicator),
                "Expected principal type indicator to be 1 (standard) or 2 (contract), got {type_indicator}"
            );

            // Extract the standard principal data from the buffer.
            let standard_principal_data: [u8; 20] = value[2..22]
                .try_into()
                .map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))?;

            let standard_principal = StandardPrincipalData(
                value[1],                // Version
                standard_principal_data, // Data
            );

            // If this is a standard principal, then we are done and can return.
            if type_indicator == 1 {
                return Ok(Value::Principal(PrincipalData::Standard(
                    standard_principal,
                )));
            }

            // Parse out the contract name length
            let name_len_bytes: [u8; 2] = value[23..24]
                .try_into()
                .map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))?;
            let name_len = u16::from_le_bytes(name_len_bytes) as usize;

            let mut name: &[u8] = &[];
            if name_len > 0 {
                name = &value[25..25 + name_len];
            }

            // Convert the name to a string
            let name_str =
                std::str::from_utf8(name).map_err(|_| Error::Wasm(WasmError::ValueTypeMismatch))?;

            // Return the contract principal
            Ok(Value::Principal(PrincipalData::Contract(
                QualifiedContractIdentifier {
                    issuer: standard_principal,
                    name: name_str.into(),
                },
            )))
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(list)) => {
            todo!("type not yet implemented: {:?}", ty)
        }
        TypeSignature::CallableType(callable) => {
            todo!("type not yet implemented: {:?}", ty)
        }
        TypeSignature::ListUnionType(union) => {
            // TODO: We probably need to include a type marker during serialization to be able to determine the correct
            // type for this case.

            // TODO: Assert that the type in the buffer is one of the allowed types.
            todo!("type not yet implemented: {:?}", ty)
        }
        TypeSignature::TupleType(_) => {
            todo!("type not yet implemented: {:?}", ty)
        }
        TypeSignature::NoType => {
            unimplemented!("NoType is not supported, this should never be reached.")
        }
        TypeSignature::TraitReferenceType(_) => {
            unimplemented!("TraitReferenceType is not supported, this should never be reached.")
        }
    }
}

/// Gets the type indicator value for the provided `Value`. This indicator is used to
/// prefix serialized values so that the type can be known during deserialization, especially
/// in the cases where multiple possible types are allowed in a `TypeSignature`.
fn get_type_indicator_for_clarity_value(value: &Value) -> u8 {
    match value {
        Value::UInt(_) => 1,
        Value::Int(_) => 2,
        Value::Bool(_) => 3,
        Value::Optional(_) => 4,
        Value::Response(_) => 5,
        Value::Sequence(SequenceData::String(CharType::ASCII(_))) => 6,
        Value::Sequence(SequenceData::String(CharType::UTF8(_))) => 7,
        Value::Sequence(SequenceData::Buffer(_)) => 8,
        Value::Sequence(SequenceData::List(_)) => 9,
        Value::Principal(PrincipalData::Standard(_)) => 10,
        Value::Principal(PrincipalData::Contract(_)) => 11,
        Value::CallableContract(_) => 12,
        Value::Tuple(_) => 13,
    }
}

/// Convert a Clarity 'Value' into a byte buffer. This is intended to be used
/// together with `pass_argument_to_wasm` for generating the buffer to be written
/// to WASM linear memory. More documentation regarding how values are serialized
/// can be found in the `pass_argument_to_wasm` function.
fn serialize_clarity_value(value: &Value) -> Result<Vec<u8>, Error> {
    // Allocate a vector with a reasonably large capacity to avoid reallocations
    // in the majority of cases.
    let mut result: Vec<u8> = Vec::<u8>::with_capacity(64);

    // Insert the type marker.
    result.insert(0, get_type_indicator_for_clarity_value(value));

    match value {
        Value::UInt(n) => {
            let low = (n & 0xffff_ffff_ffff_ffff) as u64;
            let high = (n >> 64) as u64;
            result.extend_from_slice(&low.to_le_bytes());
            result.extend_from_slice(&high.to_le_bytes())
        }
        Value::Int(n) => {
            let low = (n & 0xffff_ffff_ffff_ffff) as u64;
            let high = (n >> 64) as u64;
            result.extend_from_slice(&low.to_le_bytes());
            result.extend_from_slice(&high.to_le_bytes());
        }
        Value::Bool(b) => {
            result.insert(1, if *b { 1 } else { 0 });
        }
        Value::Optional(o) => {
            result.insert(1, if o.data.is_some() { 1 } else { 0 });
            if let Some(data) = &o.data {
                result.append(&mut serialize_clarity_value(&data)?);
            }
        }
        Value::Response(r) => {
            result.insert(1, if r.committed { 1 } else { 0 });
            result.append(&mut serialize_clarity_value(&r.data)?);
        }
        Value::Sequence(SequenceData::String(char_type)) => match char_type {
            CharType::ASCII(s) => {
                result.extend_from_slice(&s.data);
            }
            CharType::UTF8(s) => {
                let mut data = s
                    .data
                    .iter()
                    .flat_map(|s| s.iter())
                    .map(|e| *e)
                    .collect::<Vec<u8>>();

                result.append(&mut data);
            }
        },
        Value::Sequence(SequenceData::Buffer(b)) => {
            result.extend_from_slice(&b.data);
        }
        Value::Sequence(SequenceData::List(l)) => {
            for item in &l.data {
                let mut data = serialize_clarity_value(item)?;
                result.append(&mut data);
            }
        }
        Value::Principal(principal_type) => {
            match principal_type {
                PrincipalData::Standard(std) => {
                    // Write an indicator signalling that this is a Standard Principal (1).
                    result.insert(1, 1);
                    // Write the version
                    result.insert(2, std.0);
                    // Write the principal data
                    result.extend_from_slice(&std.1);
                }
                PrincipalData::Contract(ctr) => {
                    // Write an indicator signalling that this is a Contract Principal (2).
                    result.insert(1, 2);
                    // Write the version
                    result.insert(2, ctr.issuer.0);
                    // Write the principal data for the issuer
                    result.extend_from_slice(&ctr.issuer.1);

                    let name_bytes = ctr.name.as_bytes();
                    // Write a two-byte contract name length indicator.
                    result.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
                    // Write the name bytes.
                    result.extend_from_slice(name_bytes);
                }
            }
        }
        Value::CallableContract(ctr) => {
            // Write the contract identifier principal version.
            result.insert(1, ctr.contract_identifier.issuer.0);
            // Write the contract identifier principal data.
            result.extend_from_slice(&ctr.contract_identifier.issuer.1);

            // Handle the contract name
            let ctr_name_bytes = ctr.contract_identifier.name.as_bytes();
            // Write a two-byte contract name length indicator.
            result.extend_from_slice(&(ctr_name_bytes.len() as u16).to_le_bytes());
            // Write the contract name bytes.
            result.extend_from_slice(ctr_name_bytes);

            // If there is a trait identifier, append that after the contract principal.
            if let Some(trait_id) = &ctr.trait_identifier {
                // Write the trait identifier principal version.
                result.extend_from_slice(&[trait_id.contract_identifier.issuer.0]);
                // Write the trait identifier principal data.
                result.extend_from_slice(&trait_id.contract_identifier.issuer.1);

                // Handle the trait name
                let trait_name_bytes = trait_id.name.as_bytes();
                // Write a two-byte trait name length indicator.
                result.extend_from_slice(&(trait_name_bytes.len() as u16).to_le_bytes());
                // Write the trait name bytes.
                result.extend_from_slice(trait_name_bytes);
            }
        }
        Value::Tuple(tuple) => {
            for val in &tuple.data_map {
                let mut data = serialize_clarity_value(&val.1)?;
                result.append(&mut data);
            }
        }
    }
    Ok(result)
}

/// Convert a Clarity `Value` into one or more Wasm `Val`. If this value
/// requires writing into the Wasm memory, write it to the provided `offset`.
/// Return a vector of `Val`s that can be passed to a Wasm function, and the
/// offset, adjusted to the next available memory location.
fn pass_argument_to_wasm(
    memory: Memory,
    store: impl AsContextMut,
    value: &Value,
    offset: i32,
) -> Result<(Vec<Val>, i32), Error> {
    // Pre-allocate a vec with a capacity of 4 to avoid reallocations
    let mut buffer = Vec::<Val>::with_capacity(4);
    let mut new_offset = offset as usize;
    let mut data: Option<Box<Vec<u8>>> = None;

    match value {
        Value::UInt(n) => {
            // u128's are passed as two i64's to WASM, the first containing the low-bits,
            // the second containing the high-bits.
            let low = (n & 0xffff_ffff_ffff_ffff) as u64;
            let high = (n >> 64) as u64;
            buffer.extend_from_slice(&[Val::I64(low as i64), Val::I64(high as i64)]);
        }
        Value::Int(n) => {
            // i128's are passed as two i64's to WASM, the first containing the low-bits,
            // the second containing the high-bits.
            let low = (n & 0xffff_ffff_ffff_ffff) as u64;
            let high = (n >> 64) as u64;
            buffer.extend_from_slice(&[Val::I64(low as i64), Val::I64(high as i64)]);
        }
        Value::Bool(b) => {
            // Booleans are expressed as a single value, 1 = true, 0 = false.
            buffer.extend_from_slice(&[Val::I32(if *b { 1 } else { 0 })]);
        }
        Value::Optional(o) => {
            // Indicator for Some = 1, None = 0.
            buffer.insert(0, Val::I32(if o.data.is_some() { 1 } else { 0 }));

            // If the optional data is `Some`, serialize the value (recursively) and write to
            // memory at the current offset. If the optional data is `None`, no memory
            // will be written and this will be indicated by the `Val(0)` above.
            if let Some(val) = o.data.clone() {
                data = Some(Box::new(serialize_clarity_value(&val)?));
            }
        }
        Value::Response(r) => {
            // Indicator for Ok = 1, Err = 0.
            buffer.insert(0, Val::I32(if r.committed { 1 } else { 0 }));

            // Regardless whether or not the response is Ok or Err, the value will be
            // serialized and written to memory. The indicator above must be used to
            // determine the type of value contained in memory.
            data = Some(Box::new(serialize_clarity_value(&r.data)?));
        }
        Value::Sequence(SequenceData::String(CharType::ASCII(s))) => {
            // Strings will always be written to memory.
            data = Some(Box::new(s.data.clone()));
        }
        Value::Sequence(SequenceData::String(CharType::UTF8(s))) => {
            // For a UTF8 string we need to flatten the input (a vec of vecs, each character is four
            // bytes) prior to writing it to linear memory.
            let bytes = s
                .data
                .clone()
                .into_iter()
                .flat_map(|s| s)
                .collect::<Vec<u8>>();

            // Strings will always be written to memory.
            data = Some(Box::new(bytes));
        }
        Value::Sequence(SequenceData::Buffer(b)) => {
            // This is basically the exact same thing as an ASCII string, it just works
            // directly with bytes.
            data = Some(Box::new(b.data.clone()));
        }
        // The following types will always be fully serialized to WASM memory from their
        // root type (the incoming `Value` to this function).
        Value::Sequence(SequenceData::List(_))
        | Value::Principal(_)
        | Value::CallableContract(_)
        | Value::Tuple(_) => {
            data = Some(Box::new(serialize_clarity_value(value)?));
        }
    }

    // If `data` is Some, this indicates that the value needs to be written to memory.
    // For values written to WASM memory, we follow the convention of passing two `Val(i32)`'s,
    // The first which indicates the memory offset, the second indicates the length in bytes of
    // the value in memory.
    if let Some(mem) = data {
        memory
            .write(store, offset as usize, &mem)
            .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
        new_offset += mem.len();
        buffer.extend_from_slice(&[Val::I32(offset), Val::I32(mem.len() as i32)]);
    }

    // Return the Val buffer (arguments passed to functions) and the next available memory offset.
    Ok((buffer, new_offset as i32))
}

/// Reserve space on the Wasm stack for the return value of a function, if
/// needed, and return a vector of `Val`s that can be passed to `call`, as a
/// place to store the return value, along with the new offset, which is the
/// next available memory location.
fn reserve_space_for_return<T>(
    store: &mut Store<T>,
    offset: i32,
    return_type: &TypeSignature,
) -> Result<(Vec<Val>, i32), Error>
where
    T: ClarityWasmContext,
{
    match return_type {
        TypeSignature::UIntType | TypeSignature::IntType => {
            Ok((vec![Val::I64(0), Val::I64(0)], offset))
        }
        TypeSignature::BoolType => Ok((vec![Val::I32(0)], offset)),
        TypeSignature::OptionalType(optional) => {
            let mut vals = vec![Val::I32(0)];
            let (opt_vals, adjusted) = reserve_space_for_return(store, offset, optional)?;
            vals.extend(opt_vals);
            Ok((vals, adjusted))
        }
        TypeSignature::ResponseType(response) => {
            let mut vals = vec![Val::I32(0)];
            let (mut subexpr_values, mut adjusted) =
                reserve_space_for_return(store, offset, &response.0)?;
            vals.extend(subexpr_values);
            (subexpr_values, adjusted) = reserve_space_for_return(store, adjusted, &response.1)?;
            vals.extend(subexpr_values);
            Ok((vals, adjusted))
        }
        TypeSignature::NoType => Ok((vec![Val::I32(0)], offset)),
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
            type_length,
        ))) => {
            let length: u32 = type_length.into();
            // Return values will be offset and length
            Ok((vec![Val::I32(0), Val::I32(0)], offset + length as i32))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_))) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_)) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(_)) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::CallableType(_) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::ListUnionType(_) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::PrincipalType => todo!("Return type not yet implemented: {:?}", return_type),
        TypeSignature::TraitReferenceType(_) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::TupleType(_) => todo!("Return type not yet implemented: {:?}", return_type),
    }
}

/// Convert a Wasm value into a Clarity `Value`. Depending on the type, the
/// values may be directly passed in the Wasm `Val`s or may be read from the
/// Wasm memory, via an offset and size.
/// - `type_sig` is the Clarity type of the value.
/// - `value_index` is the index of the value in the array of Wasm `Val`s.
/// - `buffer` is the array of Wasm `Val`s.
/// - `memory` is the Wasm memory.
/// - `store` is the Wasm store.
/// Returns the Clarity `Value` and the number of Wasm `Val`s that were used.
fn wasm_to_clarity_value(
    type_sig: &TypeSignature,
    value_index: usize,
    buffer: &[Val],
    memory: Memory,
    store: &mut impl AsContextMut,
) -> Result<(Option<Value>, usize), Error> {
    match type_sig {
        TypeSignature::IntType => {
            let lower = buffer[value_index]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let upper = buffer[value_index + 1]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            Ok((Some(Value::Int(((upper as i128) << 64) | lower as i128)), 2))
        }
        TypeSignature::UIntType => {
            let lower = buffer[value_index]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let upper = buffer[value_index + 1]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            Ok((
                Some(Value::UInt(((upper as u128) << 64) | lower as u128)),
                2,
            ))
        }
        TypeSignature::BoolType => Ok((
            Some(Value::Bool(
                buffer[value_index]
                    .i32()
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?
                    != 0,
            )),
            1,
        )),
        TypeSignature::OptionalType(optional) => {
            let (value, increment) =
                wasm_to_clarity_value(optional, value_index + 1, buffer, memory, store)?;
            Ok((
                if buffer[value_index]
                    .i32()
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?
                    == 1
                {
                    Some(Value::some(value.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineType,
                    ))?)?)
                } else {
                    Some(Value::none())
                },
                increment + 1,
            ))
        }
        TypeSignature::ResponseType(response) => {
            let (ok, increment_ok) =
                wasm_to_clarity_value(&response.0, value_index + 1, buffer, memory, store)?;
            let (err, increment_err) = wasm_to_clarity_value(
                &response.1,
                value_index + 1 + increment_ok,
                buffer,
                memory,
                store,
            )?;
            Ok((
                if buffer[value_index]
                    .i32()
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?
                    == 1
                {
                    Some(Value::okay(ok.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineResponseOkType,
                    ))?)?)
                } else {
                    Some(Value::error(err.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineResponseErrType,
                    ))?)?)
                },
                value_index + 1 + increment_ok + increment_err,
            ))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(_))) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let length = buffer[value_index + 1]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut string_buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(store.borrow_mut(), offset as usize, &mut string_buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            Ok((Some(Value::string_ascii_from_bytes(string_buffer)?), 2))
        }
        // A `NoType` will be a dummy value that should not be used.
        TypeSignature::NoType => Ok((None, 1)),
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_))) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_)) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(_)) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::PrincipalType => todo!("Wasm value type not implemented: {:?}", type_sig),
        TypeSignature::TupleType(_) => todo!("Wasm value type not implemented: {:?}", type_sig),
        TypeSignature::TraitReferenceType(_) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::ListUnionType(_) => todo!("Wasm value type not implemented: {:?}", type_sig),
        TypeSignature::CallableType(_) => todo!("Wasm value type not implemented: {:?}", type_sig),
    }
}
