use std::{borrow::BorrowMut, collections::HashMap, fs::File, io::Write};

use wasmtime::{AsContextMut, Caller, Engine, Linker, Memory, Module, Store, Trap, Val};

use super::{
    analysis::CheckErrors,
    callables::{DefineType, DefinedFunction},
    contracts::Contract,
    costs::CostTracker,
    database::{clarity_db::ValueResult, ClarityDatabase, DataVariableMetadata, STXBalance},
    errors::RuntimeErrorType,
    types::{
        CharType, FixedFunction, FunctionType, PrincipalData, QualifiedContractIdentifier,
        SequenceData, StandardPrincipalData, TupleData,
    },
    CallStack, ContractName, Environment, SymbolicExpression,
};
use crate::vm::{
    analysis::ContractAnalysis,
    ast::ContractAST,
    contexts::GlobalContext,
    errors::{Error, WasmError},
    functions::principals,
    types::{BufferLength, SequenceSubtype, StringSubtype, TypeSignature},
    ClarityName, ContractContext, Value,
};

enum MintAssetErrorCodes {
    ALREADY_EXIST = 1,
}
enum MintTokenErrorCodes {
    NON_POSITIVE_AMOUNT = 1,
}
enum TransferAssetErrorCodes {
    NOT_OWNED_BY = 1,
    SENDER_IS_RECIPIENT = 2,
    DOES_NOT_EXIST = 3,
}
enum TransferTokenErrorCodes {
    NOT_ENOUGH_BALANCE = 1,
    SENDER_IS_RECIPIENT = 2,
    NON_POSITIVE_AMOUNT = 3,
}

enum BurnAssetErrorCodes {
    NOT_OWNED_BY = 1,
    DOES_NOT_EXIST = 3,
}
enum BurnTokenErrorCodes {
    NOT_ENOUGH_BALANCE_OR_NON_POSITIVE = 1,
}

enum StxErrorCodes {
    NOT_ENOUGH_BALANCE = 1,
    SENDER_IS_RECIPIENT = 2,
    NON_POSITIVE_AMOUNT = 3,
    SENDER_IS_NOT_TX_SENDER = 4,
}

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
    fn get_tx_sender(&self) -> Result<PrincipalData, Error>;
    fn get_contract_caller(&self) -> Result<PrincipalData, Error>;
    fn get_tx_sponsor(&self) -> Result<Option<PrincipalData>, Error>;
    fn get_block_height(&mut self) -> u32;
    fn get_burn_block_height(&mut self) -> u32;
    fn get_stx_liquid_supply(&mut self) -> u128;
    fn is_in_regtest(&self) -> bool;
    fn is_in_mainnet(&self) -> bool;
    fn get_chain_id(&self) -> u32;
    fn push_sender(&mut self, sender: PrincipalData);
    fn pop_sender(&mut self) -> Result<PrincipalData, Error>;
    fn push_caller(&mut self, caller: PrincipalData);
    fn pop_caller(&mut self) -> Result<PrincipalData, Error>;
    fn get_stx_balance(&mut self, principal: &PrincipalData) -> u128;
    fn get_canonical_stx_balance(&mut self, principal: &PrincipalData) -> STXBalance;
    fn get_v1_unlock_height(&mut self) -> u32;
    fn get_v2_unlock_height(&mut self) -> u32;
}

/// The context used when making calls into the Wasm module.
pub struct ClarityWasmRunContext<'a, 'b, 'c> {
    pub env: &'c mut Environment<'a, 'b>,
    sender_stack: Vec<PrincipalData>,
    caller_stack: Vec<PrincipalData>,
}

impl<'a, 'b, 'c> ClarityWasmRunContext<'a, 'b, 'c> {
    pub fn new(env: &'c mut Environment<'a, 'b>) -> Self {
        ClarityWasmRunContext {
            env,
            sender_stack: vec![],
            caller_stack: vec![],
        }
    }
}

impl ClarityWasmContext for ClarityWasmRunContext<'_, '_, '_> {
    fn contract_identifier(&self) -> &QualifiedContractIdentifier {
        &self.env.contract_context.contract_identifier
    }

    fn get_var_metadata(&self, name: &str) -> Option<&DataVariableMetadata> {
        self.env.contract_context.meta_data_var.get(name)
    }

    fn lookup_variable_with_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult, Error> {
        self.env.global_context.database.lookup_variable_with_size(
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
        self.env.global_context.database.set_variable(
            contract_identifier,
            variable_name,
            value,
            variable_descriptor,
        )
    }

    fn get_tx_sender(&self) -> Result<PrincipalData, Error> {
        self.env
            .sender
            .clone()
            .ok_or(RuntimeErrorType::NoSenderInContext.into())
    }

    fn get_contract_caller(&self) -> Result<PrincipalData, Error> {
        self.env
            .caller
            .clone()
            .ok_or(RuntimeErrorType::NoCallerInContext.into())
    }

    fn get_tx_sponsor(&self) -> Result<Option<PrincipalData>, Error> {
        Ok(self.env.sponsor.clone())
    }

    fn get_block_height(&mut self) -> u32 {
        self.env.global_context.database.get_current_block_height()
    }

    fn get_burn_block_height(&mut self) -> u32 {
        self.env
            .global_context
            .database
            .get_current_burnchain_block_height()
    }

    fn get_stx_liquid_supply(&mut self) -> u128 {
        self.env.global_context.database.get_total_liquid_ustx()
    }

    fn is_in_regtest(&self) -> bool {
        self.env.global_context.database.is_in_regtest()
    }

    fn is_in_mainnet(&self) -> bool {
        self.env.global_context.mainnet
    }

    fn get_chain_id(&self) -> u32 {
        self.env.global_context.chain_id
    }

    fn push_sender(&mut self, sender: PrincipalData) {
        if let Some(current) = self.env.sender.take() {
            self.sender_stack.push(current);
        }
        self.env.sender = Some(sender);
    }

    fn pop_sender(&mut self) -> Result<PrincipalData, Error> {
        self.env
            .sender
            .take()
            .ok_or(RuntimeErrorType::NoSenderInContext.into())
            .map(|sender| {
                self.env.sender = self.sender_stack.pop();
                sender
            })
    }

    fn push_caller(&mut self, caller: PrincipalData) {
        if let Some(current) = self.env.caller.take() {
            self.caller_stack.push(current);
        }
        self.env.caller = Some(caller);
    }

    fn pop_caller(&mut self) -> Result<PrincipalData, Error> {
        self.env
            .caller
            .take()
            .ok_or(RuntimeErrorType::NoCallerInContext.into())
            .map(|caller| {
                self.env.caller = self.caller_stack.pop();
                caller
            })
    }

    fn get_stx_balance(&mut self, principal: &PrincipalData) -> u128 {
        let balance = {
            let mut snapshot = self
                .env
                .global_context
                .database
                .get_stx_balance_snapshot(principal);
            snapshot.get_available_balance()
        };
        balance
    }

    fn get_canonical_stx_balance(&mut self, principal: &PrincipalData) -> STXBalance {
        let balance = {
            let mut snapshot = self
                .env
                .global_context
                .database
                .get_stx_balance_snapshot(principal);
            snapshot.canonical_balance_repr()
        };
        balance
    }

    fn get_v1_unlock_height(&mut self) -> u32 {
        self.env.global_context.database.get_v1_unlock_height()
    }

    fn get_v2_unlock_height(&mut self) -> u32 {
        self.env.global_context.database.get_v2_unlock_height()
    }
}

/// The context used when initializing the Wasm module. It embeds the
/// `ClarityWasmRunContext`, but also includes the contract analysis data for
/// typing information.
pub struct ClarityWasmInitContext<'a, 'b> {
    // Note that we don't just use `Environment` here because we need the
    // `ContractContext` to be mutable.
    pub global_context: &'a mut GlobalContext<'b>,
    pub contract_context: &'a mut ContractContext,
    pub call_stack: &'a mut CallStack,
    pub sender: PrincipalData,
    sender_stack: Vec<PrincipalData>,
    pub caller: PrincipalData,
    caller_stack: Vec<PrincipalData>,
    pub sponsor: Option<PrincipalData>,

    /// Contract analysis data, used for typing information
    pub contract_analysis: &'a ContractAnalysis,
}

impl<'a, 'b> ClarityWasmInitContext<'a, 'b> {
    pub fn new(
        global_context: &'a mut GlobalContext<'b>,
        contract_context: &'a mut ContractContext,
        call_stack: &'a mut CallStack,
        publisher: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract_analysis: &'a ContractAnalysis,
    ) -> Self {
        ClarityWasmInitContext {
            global_context,
            contract_context,
            call_stack,
            sender: publisher.clone(),
            sender_stack: vec![],
            caller: publisher,
            caller_stack: vec![],
            sponsor,
            contract_analysis,
        }
    }
}

impl ClarityWasmContext for ClarityWasmInitContext<'_, '_> {
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

    fn get_tx_sender(&self) -> Result<PrincipalData, Error> {
        Ok(self.sender.clone())
    }

    fn get_contract_caller(&self) -> Result<PrincipalData, Error> {
        Ok(self.caller.clone())
    }

    fn get_tx_sponsor(&self) -> Result<Option<PrincipalData>, Error> {
        Ok(self.sponsor.clone())
    }

    fn get_block_height(&mut self) -> u32 {
        self.global_context.database.get_current_block_height()
    }

    fn get_burn_block_height(&mut self) -> u32 {
        self.global_context
            .database
            .get_current_burnchain_block_height()
    }

    fn get_stx_liquid_supply(&mut self) -> u128 {
        self.global_context.database.get_total_liquid_ustx()
    }

    fn is_in_regtest(&self) -> bool {
        self.global_context.database.is_in_regtest()
    }

    fn is_in_mainnet(&self) -> bool {
        self.global_context.mainnet
    }

    fn get_chain_id(&self) -> u32 {
        self.global_context.chain_id
    }

    fn push_sender(&mut self, sender: PrincipalData) {
        self.sender_stack
            .push(std::mem::replace(&mut self.sender, sender));
    }

    fn pop_sender(&mut self) -> Result<PrincipalData, Error> {
        let sender = self.sender_stack.pop().ok_or(Error::Runtime(
            RuntimeErrorType::NoSenderInContext.into(),
            Some(self.call_stack.make_stack_trace()),
        ))?;
        Ok(std::mem::replace(&mut self.sender, sender))
    }

    fn push_caller(&mut self, caller: PrincipalData) {
        self.caller_stack
            .push(std::mem::replace(&mut self.caller, caller));
    }

    fn pop_caller(&mut self) -> Result<PrincipalData, Error> {
        let caller = self.caller_stack.pop().ok_or(Error::Runtime(
            RuntimeErrorType::NoCallerInContext.into(),
            Some(self.call_stack.make_stack_trace()),
        ))?;
        Ok(std::mem::replace(&mut self.caller, caller))
    }

    fn get_stx_balance(&mut self, principal: &PrincipalData) -> u128 {
        let balance = {
            let mut snapshot = self
                .global_context
                .database
                .get_stx_balance_snapshot(principal);
            snapshot.get_available_balance()
        };
        balance
    }

    fn get_canonical_stx_balance(&mut self, principal: &PrincipalData) -> STXBalance {
        let balance = {
            let mut snapshot = self
                .global_context
                .database
                .get_stx_balance_snapshot(principal);
            snapshot.canonical_balance_repr()
        };
        balance
    }

    fn get_v1_unlock_height(&mut self) -> u32 {
        self.global_context.database.get_v1_unlock_height()
    }

    fn get_v2_unlock_height(&mut self) -> u32 {
        self.global_context.database.get_v2_unlock_height()
    }
}

fn link_define_functions(linker: &mut Linker<ClarityWasmInitContext>) -> Result<(), Error> {
    link_define_function_fn(linker)?;
    link_define_variable_fn(linker)
}

fn link_err_define_functions(linker: &mut Linker<ClarityWasmRunContext>) -> Result<(), Error> {
    link_define_function_fn_error(linker)?;
    link_define_variable_fn_error(linker)
}

fn link_runtime_functions<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    link_get_variable_fn(linker)?;
    link_set_variable_fn(linker)?;
    link_tx_sender_fn(linker)?;
    link_contract_caller_fn(linker)?;
    link_tx_sponsor_fn(linker)?;
    link_block_height_fn(linker)?;
    link_burn_block_height_fn(linker)?;
    link_stx_liquid_supply_fn(linker)?;
    link_is_in_regtest_fn(linker)?;
    link_is_in_mainnet_fn(linker)?;
    link_chain_id_fn(linker)?;
    link_enter_as_contract_fn(linker)?;
    link_exit_as_contract_fn(linker)?;
    link_stx_get_balance_fn(linker)?;
    link_stx_account_fn(linker)?;
    // link_stx_burn_fn(linker)?;
    // link_stx_transfer_fn(linker)?;
    // link_ft_get_supply_fn(linker)?;
    // link_ft_get_balance_fn(linker)?;
    // link_ft_burn_fn(linker)?;
    // link_ft_mint_fn(linker)?;
    // link_ft_transfer_fn(linker)?;
    // link_nft_get_owner_fn(linker)?;
    // link_nft_burn_fn(linker)?;
    // link_nft_mint_fn(linker)?;
    // link_nft_transfer_fn(linker)?;
    link_log(linker)
}

/// Initialize a contract, executing all of the top-level expressions and
/// registering all of the definitions in the context.
pub fn initialize_contract(
    global_context: &mut GlobalContext,
    contract_context: &mut ContractContext,
    sponsor: Option<PrincipalData>,
    contract_analysis: &ContractAnalysis,
) -> Result<Option<Value>, Error> {
    let publisher: PrincipalData = contract_context.contract_identifier.issuer.clone().into();
    let mut call_stack = CallStack::new();
    let context = ClarityWasmInitContext::new(
        global_context,
        contract_context,
        &mut call_stack,
        publisher,
        sponsor,
        contract_analysis,
    );
    let engine = Engine::default();
    let module = context.contract_context.with_wasm_module(|wasm_module| {
        Module::from_binary(&engine, wasm_module)
            .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))
    })?;
    let mut store = Store::new(&engine, context);
    let mut linker = Linker::new(&engine);

    // Link in the host interface functions.
    link_define_functions(&mut linker)?;
    link_runtime_functions(&mut linker)?;

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
    store.data_mut().contract_context.set_wasm_module(
        module
            .serialize()
            .map_err(|e| Error::Wasm(WasmError::WasmCompileFailed(e)))?,
    );

    Ok(None)
}

/// Call a function in the contract.
pub fn call_function<'a, 'b, 'c>(
    function_name: &str,
    args: &[Value],
    env: &mut Environment<'a, 'b>,
) -> Result<Value, Error> {
    let context = ClarityWasmRunContext::new(env);
    let engine = Engine::default();
    let module = context
        .env
        .contract_context
        .with_wasm_module(|wasm_module| unsafe {
            Module::deserialize(&engine, wasm_module)
                .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))
        })?;
    let mut store = Store::new(&engine, context);
    let mut linker = Linker::new(&engine);

    // Link in the host interface functions.
    link_err_define_functions(&mut linker)?;
    link_runtime_functions(&mut linker)?;

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
        .env
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
                        .contract_context
                        .contract_identifier
                        .to_string(),
                    Some(fixed_type.returns.clone()),
                );

                // Insert this function into the context
                caller
                    .data_mut()
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

                let contract = caller.data().contract_context.contract_identifier.clone();

                // Read the initial value from the memory
                let value = read_from_wasm(&mut caller, &value_type, value_offset, value_length)?;

                caller
                    .data_mut()
                    .contract_context
                    .persisted_names
                    .insert(ClarityName::try_from(name.clone())?);

                caller
                    .data_mut()
                    .global_context
                    .add_memory(value_type.type_size()? as u64)
                    .map_err(|e| Error::from(e))?;

                caller
                    .data_mut()
                    .global_context
                    .add_memory(value.size() as u64)
                    .map_err(|e| Error::from(e))?;

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
             _return_length: i32| {
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
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                write_to_wasm(
                    &mut caller,
                    memory,
                    &data_types.value_type,
                    return_offset,
                    &value,
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

/// Link host interface function, `tx_sender`, into the Wasm module.
/// This function is called for use of the builtin variable, `tx-sender`.
fn link_tx_sender_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "tx_sender",
            |mut caller: Caller<'_, T>, return_offset: i32, return_length: i32| {
                let sender = caller.data().get_tx_sender()?;

                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                write_to_wasm(
                    &mut caller,
                    memory,
                    &TypeSignature::PrincipalType,
                    return_offset,
                    &Value::Principal(sender),
                )?;

                Ok((return_offset, return_length))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "tx_sender".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `contract_caller`, into the Wasm module.
/// This function is called for use of the builtin variable, `contract-caller`.
fn link_contract_caller_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "contract_caller",
            |mut caller: Caller<'_, T>, return_offset: i32, return_length: i32| {
                let contract_caller = caller.data().get_contract_caller()?;

                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                write_to_wasm(
                    &mut caller,
                    memory,
                    &TypeSignature::PrincipalType,
                    return_offset,
                    &Value::Principal(contract_caller),
                )?;

                Ok((return_offset, return_length))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "contract_caller".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `tx_sponsor`, into the Wasm module.
/// This function is called for use of the builtin variable, `tx-sponsor`.
fn link_tx_sponsor_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "tx_sponsor",
            |mut caller: Caller<'_, T>, return_offset: i32, return_length: i32| {
                let opt_sponsor = caller.data().get_tx_sponsor()?;
                if let Some(sponsor) = opt_sponsor {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|export| export.into_memory())
                        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                    write_to_wasm(
                        &mut caller,
                        memory,
                        &TypeSignature::PrincipalType,
                        return_offset,
                        &Value::Principal(sponsor),
                    )?;

                    Ok((1i32, return_offset, return_length))
                } else {
                    Ok((0i32, return_offset, return_length))
                }
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "tx_sponsor".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `block_height`, into the Wasm module.
/// This function is called for use of the builtin variable, `block-height`.
fn link_block_height_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap("clarity", "block_height", |mut caller: Caller<'_, T>| {
            let height = caller.data_mut().get_block_height();
            Ok((height as i64, 0i64))
        })
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "block_height".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `burn_block_height`, into the Wasm module.
/// This function is called for use of the builtin variable,
/// `burn-block-height`.
fn link_burn_block_height_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "burn_block_height",
            |mut caller: Caller<'_, T>| {
                let height = caller.data_mut().get_burn_block_height();
                Ok((height as i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "burn_block_height".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `stx_liquid_supply`, into the Wasm module.
/// This function is called for use of the builtin variable,
/// `stx-liquid-supply`.
fn link_stx_liquid_supply_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "stx_liquid_supply",
            |mut caller: Caller<'_, T>| {
                let supply = caller.data_mut().get_stx_liquid_supply();
                let upper = (supply >> 64) as u64;
                let lower = supply as u64;
                Ok((lower as i64, upper as i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "stx_liquid_supply".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `is_in_regtest`, into the Wasm module.
/// This function is called for use of the builtin variable,
/// `is-in-regtest`.
fn link_is_in_regtest_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap("clarity", "is_in_regtest", |caller: Caller<'_, T>| {
            if caller.data().is_in_regtest() {
                Ok(1i32)
            } else {
                Ok(0i32)
            }
        })
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "is_in_regtest".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `is_in_mainnet`, into the Wasm module.
/// This function is called for use of the builtin variable,
/// `is-in-mainnet`.
fn link_is_in_mainnet_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap("clarity", "is_in_mainnet", |caller: Caller<'_, T>| {
            if caller.data().is_in_mainnet() {
                Ok(1i32)
            } else {
                Ok(0i32)
            }
        })
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "is_in_mainnet".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `chain_id`, into the Wasm module.
/// This function is called for use of the builtin variable,
/// `chain-id`.
fn link_chain_id_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap("clarity", "chain_id", |caller: Caller<'_, T>| {
            let chain_id = caller.data().get_chain_id();
            Ok((chain_id as i64, 0i64))
        })
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "chain_id".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `enter_as_contract`, into the Wasm module.
/// This function is called before processing the inner-expression of
/// `as-contract`.
fn link_enter_as_contract_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "enter_as_contract",
            |mut caller: Caller<'_, T>| {
                let contract_principal: PrincipalData =
                    caller.data().contract_identifier().clone().into();
                caller.data_mut().push_sender(contract_principal.clone());
                caller.data_mut().push_caller(contract_principal);
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "enter_as_contract".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `exit_as_contract`, into the Wasm module.
/// This function is after before processing the inner-expression of
/// `as-contract`, and is used to restore the caller and sender.
fn link_exit_as_contract_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "exit_as_contract",
            |mut caller: Caller<'_, T>| {
                caller.data_mut().pop_sender()?;
                caller.data_mut().pop_caller()?;
                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "exit_as_contract".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `stx_get_balance`, into the Wasm module.
/// This function is called for the clarity expression, `stx-get-balance`.
fn link_stx_get_balance_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "stx_get_balance",
            |mut caller: Caller<'_, T>, principal_offset: i32, principal_length: i32| {
                // Read the principal from the Wasm memory
                let value = read_from_wasm(
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    principal_offset,
                    principal_length,
                )?;
                let principal = value_as_principal(&value)?;

                let balance = caller.data_mut().get_stx_balance(principal);
                let high = (balance >> 64) as u64;
                let low = (balance & 0xffff_ffff_ffff_ffff) as u64;
                Ok((low, high))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "stx_get_balance".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `stx_account`, into the Wasm module.
/// This function is called for the clarity expression, `stx-account`.
fn link_stx_account_fn<T>(linker: &mut Linker<T>) -> Result<(), Error>
where
    T: ClarityWasmContext,
{
    linker
        .func_wrap(
            "clarity",
            "stx_account",
            |mut caller: Caller<'_, T>, principal_offset: i32, principal_length: i32| {
                // Read the principal from the Wasm memory
                let value = read_from_wasm(
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    principal_offset,
                    principal_length,
                )?;
                let principal = value_as_principal(&value)?;

                let account = caller.data_mut().get_canonical_stx_balance(principal);
                let v1_unlock_ht = caller.data_mut().get_v1_unlock_height();
                let v2_unlock_ht = caller.data_mut().get_v2_unlock_height();

                let locked = account.amount_locked();
                let locked_high = (locked >> 64) as u64;
                let locked_low = (locked & 0xffff_ffff_ffff_ffff) as u64;
                let unlock_height = account.effective_unlock_height(v1_unlock_ht, v2_unlock_ht);
                let unlocked = account.amount_unlocked();
                let unlocked_high = (unlocked >> 64) as u64;
                let unlocked_low = (unlocked & 0xffff_ffff_ffff_ffff) as u64;

                // Return value is a tuple: `{locked: uint, unlock-height: uint, unlocked: uint}`
                Ok((
                    locked_low,
                    locked_high,
                    unlock_height as i64,
                    0i64,
                    unlocked_low,
                    unlocked_high,
                ))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "stx_account".to_string(),
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
        TypeSignature::PrincipalType => {
            debug_assert!(length >= 25 && length <= 153);
            let mut current_offset = offset as usize;
            let mut version: [u8; 1] = [0];
            let mut hash: [u8; 20] = [0; 20];
            memory
                .read(caller.borrow_mut(), current_offset, &mut version)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += 1;
            memory
                .read(caller.borrow_mut(), current_offset, &mut hash)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += 20;
            let principal = StandardPrincipalData(version[0], hash);
            let mut contract_length_buf: [u8; 4] = [0; 4];
            memory
                .read(
                    caller.borrow_mut(),
                    current_offset,
                    &mut contract_length_buf,
                )
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += 4;
            let contract_length = u32::from_le_bytes(contract_length_buf);
            if contract_length == 0 {
                Ok(Value::Principal(principal.into()))
            } else {
                let mut contract_name: Vec<u8> = vec![0; contract_length as usize];
                memory
                    .read(caller.borrow_mut(), current_offset, &mut contract_name)
                    .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
                let contract_name = String::from_utf8(contract_name)
                    .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
                Ok(Value::Principal(PrincipalData::Contract(
                    QualifiedContractIdentifier {
                        issuer: principal,
                        name: ContractName::try_from(contract_name)?,
                    },
                )))
            }
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

fn value_as_principal(value: &Value) -> Result<&PrincipalData, Error> {
    match value {
        Value::Principal(p) => Ok(p),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

/// Write a value to the Wasm memory at `offset` with `length` given the
/// provided Clarity `TypeSignature`.'
fn write_to_wasm(
    mut store: impl AsContextMut,
    memory: Memory,
    ty: &TypeSignature,
    offset: i32,
    value: &Value,
) -> Result<i32, Error> {
    match ty {
        TypeSignature::IntType => {
            let mut buffer: [u8; 8] = [0; 8];
            let i = value_as_i128(&value)?;
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            buffer.copy_from_slice(&low.to_le_bytes());
            memory
                .write(store.as_context_mut(), offset as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            buffer.copy_from_slice(&high.to_le_bytes());
            memory
                .write(store.as_context_mut(), (offset + 8) as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok(16)
        }
        TypeSignature::UIntType => {
            let mut buffer: [u8; 8] = [0; 8];
            let i = value_as_u128(&value)?;
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            buffer.copy_from_slice(&low.to_le_bytes());
            memory
                .write(store.as_context_mut(), offset as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            buffer.copy_from_slice(&high.to_le_bytes());
            memory
                .write(store.as_context_mut(), (offset + 8) as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok(16)
        }
        TypeSignature::SequenceType(_subtype) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ResponseType(_sig) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::BoolType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::CallableType(_subtype) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ListUnionType(_subtypes) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::NoType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::OptionalType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::PrincipalType => {
            let principal = value_as_principal(&value)?;
            let (standard, contract_name) = match principal {
                PrincipalData::Standard(s) => (s, ""),
                PrincipalData::Contract(contract_identifier) => (
                    &contract_identifier.issuer,
                    contract_identifier.name.as_str(),
                ),
            };
            let mut written = 0;
            memory
                .write(
                    store.as_context_mut(),
                    (offset + written) as usize,
                    &[standard.0],
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            written += 1;
            memory
                .write(
                    store.as_context_mut(),
                    (offset + written) as usize,
                    &standard.1,
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            written += standard.1.len() as i32;
            if !contract_name.is_empty() {
                memory
                    .write(
                        store.as_context_mut(),
                        (offset + written) as usize,
                        &[contract_name.len() as u8],
                    )
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 1;
                memory
                    .write(
                        store.as_context_mut(),
                        (offset + written) as usize,
                        contract_name.as_bytes(),
                    )
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += contract_name.len() as i32;
            }
            Ok(written)
        }
        TypeSignature::TraitReferenceType(_trait_id) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TupleType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
    }
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
        Value::Sequence(SequenceData::List(l)) => {
            let mut buffer = vec![Val::I32(offset)];
            let mut adjusted_offset = offset;
            for item in &l.data {
                let len = write_to_wasm(
                    store.as_context_mut(),
                    memory,
                    l.type_signature.get_list_item_type(),
                    adjusted_offset,
                    item,
                )?;
                adjusted_offset += len;
            }
            buffer.push(Val::I32(adjusted_offset - offset));
            Ok((buffer, adjusted_offset))
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
        TypeSignature::PrincipalType => {
            // Standard principal is a 1 byte version and a 20 byte Hash160.
            // Then there is an int32 for the contract name length, followed by
            // the contract name, which has a max length of 128.
            let length: u32 = 1 + 20 + 1 + 128;
            // Return values will be offset and length
            Ok((vec![Val::I32(0), Val::I32(0)], offset + length as i32))
        }
        TypeSignature::TraitReferenceType(_trait_id) => {
            todo!("Return type not yet implemented: {:?}", return_type)
        }
        TypeSignature::TupleType(type_sig) => {
            let mut vals = vec![];
            let mut adjusted = offset;
            for ty in type_sig.get_type_map().values() {
                let (subexpr_values, new_offset) = reserve_space_for_return(store, adjusted, ty)?;
                vals.extend(subexpr_values);
                adjusted = new_offset;
            }
            Ok((vals, adjusted))
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
        TypeSignature::PrincipalType => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut principal_bytes: [u8; 21] = [0; 21];
            memory
                .read(store.borrow_mut(), offset as usize, &mut principal_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            let mut buffer: [u8; 1] = [0; 1];
            memory
                .read(store.borrow_mut(), offset as usize + 21, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            let standard =
                StandardPrincipalData(principal_bytes[0], principal_bytes[1..].try_into().unwrap());
            let contract_name_length = u8::from_le_bytes(buffer);
            if contract_name_length == 0 {
                Ok((
                    Some(Value::Principal(PrincipalData::Standard(standard))),
                    1 + 20 + 1,
                ))
            } else {
                let mut contract_name: Vec<u8> = vec![0; contract_name_length as usize];
                memory
                    .read(
                        store.borrow_mut(),
                        (offset + 22) as usize,
                        &mut contract_name,
                    )
                    .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
                Ok((
                    Some(Value::Principal(PrincipalData::Contract(
                        QualifiedContractIdentifier {
                            issuer: standard,
                            name: ContractName::try_from(
                                String::from_utf8(contract_name).map_err(|e| {
                                    Error::Wasm(WasmError::UnableToReadIdentifier(e))
                                })?,
                            )?,
                        },
                    ))),
                    1 + 20 + 1 + contract_name_length as usize,
                ))
            }
        }
        TypeSignature::TupleType(t) => {
            let mut index = value_index;
            let mut data_map = Vec::new();
            for (name, ty) in t.get_type_map() {
                let (value, increment) = wasm_to_clarity_value(ty, index, buffer, memory, store)?;
                data_map.push((
                    name.clone(),
                    value.ok_or(Error::Unchecked(CheckErrors::BadTupleConstruction))?,
                ));
                index += increment;
            }
            let tuple = TupleData::from_data(data_map)?;
            Ok((Some(tuple.into()), index))
        }
        TypeSignature::TraitReferenceType(_t) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::ListUnionType(_lu) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::CallableType(_c) => todo!("Wasm value type not implemented: {:?}", type_sig),
    }
}
