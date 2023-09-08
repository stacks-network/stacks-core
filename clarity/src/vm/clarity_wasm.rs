use std::{borrow::BorrowMut, collections::HashMap, fs::File, io::Write};

use wasmtime::{AsContextMut, Caller, Engine, Linker, Memory, Module, Store, Trap, Val};

use super::{
    analysis::CheckErrors,
    callables::{DefineType, DefinedFunction},
    contracts::Contract,
    costs::CostTracker,
    database::{clarity_db::ValueResult, ClarityDatabase, DataVariableMetadata},
    errors::RuntimeErrorType,
    types::{CharType, FixedFunction, FunctionType, QualifiedContractIdentifier, SequenceData},
    SymbolicExpression,
};
use crate::vm::{
    analysis::ContractAnalysis,
    ast::ContractAST,
    contexts::GlobalContext,
    errors::{Error, WasmError},
    types::{BufferLength, SequenceSubtype, StringSubtype, TypeSignature},
    ClarityName, ContractContext, Value,
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

    // Save the compiled Wasm module into the contract context
    store
        .data_mut()
        .run_context
        .contract_context
        .set_wasm_module(
            module
                .serialize()
                .map_err(|e| Error::Wasm(WasmError::WasmCompileFailed(e)))?,
        );

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
    let module = context
        .contract_context
        .with_wasm_module(|wasm_module| unsafe {
            Module::deserialize(&engine, wasm_module)
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
        .as_ref()
        .ok_or(Error::Wasm(WasmError::ExpectedReturnValue))?
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
                    Some(fixed_type.returns.clone()),
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
            |mut _caller: Caller<'_, T>,
             _kind: i32,
             _name_offset: i32,
             _name_length: i32|
             -> Result<(), _> {
                // This should be a Anyhow error, but we don't have it as a dependency.
                // `?` does the trick.
                let _ = Err(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?;
                unreachable!();
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

    match ty {
        TypeSignature::UIntType => {
            debug_assert!(
                length == 16,
                "expected uint length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            memory
                .read(caller.borrow_mut(), offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let low = u64::from_le_bytes(buffer) as u128;
            memory
                .read(caller.borrow_mut(), (offset + 8) as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let high = u64::from_le_bytes(buffer) as u128;
            Ok(Value::UInt((high << 64) | low))
        }
        TypeSignature::IntType => {
            debug_assert!(
                length == 16,
                "expected int length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            memory
                .read(caller.borrow_mut(), offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let low = u64::from_le_bytes(buffer) as u128;
            memory
                .read(caller.borrow_mut(), (offset + 8) as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let high = u64::from_le_bytes(buffer) as u128;
            Ok(Value::Int(((high << 64) | low) as i128))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
            type_length,
        ))) => {
            debug_assert!(
                type_length >= &BufferLength::try_from(length as u32)?,
                "expected string length to be less than the type length"
            );
            let mut buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(caller, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            Value::string_ascii_from_bytes(buffer)
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_s))) => {
            todo!("type not yet implemented: {:?}", ty)
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_b)) => {
            todo!("type not yet implemented: {:?}", ty)
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(_l)) => {
            todo!("type not yet implemented: {:?}", ty)
        }
        TypeSignature::ResponseType(_r) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::BoolType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::CallableType(_subtype) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ListUnionType(_subtypes) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::NoType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::OptionalType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::PrincipalType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TraitReferenceType(_trait_id) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TupleType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
    }
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
        TypeSignature::SequenceType(_subtype) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ResponseType(_sig) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::BoolType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::CallableType(_subtype) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ListUnionType(_subtypes) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::NoType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::OptionalType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::PrincipalType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TraitReferenceType(_trait_id) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TupleType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
    };
    Ok(())
}

/// Convert a Clarity `Value` into one or more Wasm `Val`. If this value
/// requires writing into the Wasm memory, write it to the provided `offset`.
/// Return a vector of `Val`s that can be passed to a Wasm function, and the
/// offset, adjusted to the next available memory location.
fn pass_argument_to_wasm(
    memory: Memory,
    mut store: impl AsContextMut,
    value: &Value,
    offset: i32,
) -> Result<(Vec<Val>, i32), Error> {
    match value {
        Value::UInt(n) => {
            let high = (n >> 64) as u64;
            let low = (n & 0xffff_ffff_ffff_ffff) as u64;
            let buffer = vec![Val::I64(low as i64), Val::I64(high as i64)];
            Ok((buffer, offset))
        }
        Value::Int(n) => {
            let high = (n >> 64) as u64;
            let low = (n & 0xffff_ffff_ffff_ffff) as u64;
            let buffer = vec![Val::I64(low as i64), Val::I64(high as i64)];
            Ok((buffer, offset))
        }
        Value::Bool(b) => Ok((vec![Val::I32(if *b { 1 } else { 0 })], offset)),
        Value::Optional(o) => {
            let mut buffer = vec![Val::I32(if o.data.is_some() { 1 } else { 0 })];
            let (inner, new_offset) = pass_argument_to_wasm(
                memory,
                store,
                o.data
                    .as_ref()
                    .map_or(&Value::none(), |boxed_value| &boxed_value),
                offset + 1,
            )?;
            buffer.extend(inner);
            Ok((buffer, new_offset))
        }
        Value::Response(r) => {
            let mut buffer = vec![Val::I32(if r.committed { 1 } else { 0 })];
            let (inner, new_offset) = if r.committed {
                pass_argument_to_wasm(memory, store, &r.data, offset + 1)?
            } else {
                pass_argument_to_wasm(memory, store, &r.data, offset + 1)?
            };
            buffer.extend(inner);
            Ok((buffer, new_offset))
        }
        Value::Sequence(SequenceData::String(CharType::ASCII(s))) => {
            // For a string, write the bytes into the memory, then pass the
            // offset and length to the Wasm function.
            let buffer = vec![Val::I32(offset), Val::I32(s.data.len() as i32)];
            memory
                .write(store.borrow_mut(), offset as usize, s.data.as_slice())
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            let adjusted_offset = offset + s.data.len() as i32;
            Ok((buffer, adjusted_offset))
        }
        Value::Sequence(SequenceData::String(CharType::UTF8(_s))) => {
            todo!("Value type not yet implemented: {:?}", value)
        }
        Value::Sequence(SequenceData::Buffer(_b)) => {
            todo!("Value type not yet implemented: {:?}", value)
        }
        Value::Sequence(SequenceData::List(_l)) => {
            todo!("Value type not yet implemented: {:?}", value)
        }
        Value::Principal(_p) => todo!("Value type not yet implemented: {:?}", value),
        Value::CallableContract(_c) => todo!("Value type not yet implemented: {:?}", value),
        Value::Tuple(_t) => todo!("Value type not yet implemented: {:?}", value),
    }
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
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_s))) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_b)) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(_l)) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::CallableType(_subtype) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::ListUnionType(_subtypes) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::PrincipalType => todo!("Return type not yet implemented: {:?}", return_type),
        TypeSignature::TraitReferenceType(_trait_id) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::TupleType(_type_sig) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
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
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_s))) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_b)) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(_l)) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::PrincipalType => todo!("Wasm value type not implemented: {:?}", type_sig),
        TypeSignature::TupleType(_t) => todo!("Wasm value type not implemented: {:?}", type_sig),
        TypeSignature::TraitReferenceType(_t) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::ListUnionType(_lu) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::CallableType(_c) => todo!("Wasm value type not implemented: {:?}", type_sig),
    }
}
