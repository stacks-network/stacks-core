use std::{
    borrow::BorrowMut,
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Write,
};

use wasmtime::{AsContextMut, Caller, Engine, Linker, Memory, Module, Store, Trap, Val, ValType};

use super::{
    analysis::CheckErrors,
    callables::{DefineType, DefinedFunction},
    contracts::Contract,
    costs::CostTracker,
    database::{clarity_db::ValueResult, ClarityDatabase, DataVariableMetadata, STXBalance},
    errors::RuntimeErrorType,
    events::*,
    types::{
        ASCIIData, AssetIdentifier, BlockInfoProperty, BuffData, BurnBlockInfoProperty, CharType,
        FixedFunction, FunctionType, OptionalData, PrincipalData, QualifiedContractIdentifier,
        ResponseData, SequenceData, StandardPrincipalData, TraitIdentifier, TupleData,
        TupleTypeSignature, BUFF_1, BUFF_32,
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

/// The context used when making calls into the Wasm module.
pub struct ClarityWasmContext<'a, 'b> {
    pub global_context: &'a mut GlobalContext<'b>,
    contract_context: Option<&'a ContractContext>,
    contract_context_mut: Option<&'a mut ContractContext>,
    pub call_stack: &'a mut CallStack,
    pub sender: Option<PrincipalData>,
    pub caller: Option<PrincipalData>,
    pub sponsor: Option<PrincipalData>,
    sender_stack: Vec<PrincipalData>,
    caller_stack: Vec<PrincipalData>,

    /// Contract analysis data, used for typing information, and only available
    /// when initializing a contract. Should always be `Some` when initializing
    /// a contract, and `None` otherwise.
    pub contract_analysis: Option<&'a ContractAnalysis>,
}

impl<'a, 'b> ClarityWasmContext<'a, 'b> {
    pub fn new_init(
        global_context: &'a mut GlobalContext<'b>,
        contract_context: &'a mut ContractContext,
        call_stack: &'a mut CallStack,
        sender: Option<PrincipalData>,
        caller: Option<PrincipalData>,
        sponsor: Option<PrincipalData>,
        contract_analysis: Option<&'a ContractAnalysis>,
    ) -> Self {
        ClarityWasmContext {
            global_context,
            contract_context: None,
            contract_context_mut: Some(contract_context),
            call_stack,
            sender,
            caller,
            sponsor,
            sender_stack: vec![],
            caller_stack: vec![],
            contract_analysis,
        }
    }

    pub fn new_run(
        global_context: &'a mut GlobalContext<'b>,
        contract_context: &'a ContractContext,
        call_stack: &'a mut CallStack,
        sender: Option<PrincipalData>,
        caller: Option<PrincipalData>,
        sponsor: Option<PrincipalData>,
        contract_analysis: Option<&'a ContractAnalysis>,
    ) -> Self {
        ClarityWasmContext {
            global_context,
            contract_context: Some(contract_context),
            contract_context_mut: None,
            call_stack,
            sender,
            caller,
            sponsor,
            sender_stack: vec![],
            caller_stack: vec![],
            contract_analysis,
        }
    }

    fn push_sender(&mut self, sender: PrincipalData) {
        if let Some(current) = self.sender.take() {
            self.sender_stack.push(current);
        }
        self.sender = Some(sender);
    }

    fn pop_sender(&mut self) -> Result<PrincipalData, Error> {
        self.sender
            .take()
            .ok_or(RuntimeErrorType::NoSenderInContext.into())
            .map(|sender| {
                self.sender = self.sender_stack.pop();
                sender
            })
    }

    fn push_caller(&mut self, caller: PrincipalData) {
        if let Some(current) = self.caller.take() {
            self.caller_stack.push(current);
        }
        self.caller = Some(caller);
    }

    fn pop_caller(&mut self) -> Result<PrincipalData, Error> {
        self.caller
            .take()
            .ok_or(RuntimeErrorType::NoCallerInContext.into())
            .map(|caller| {
                self.caller = self.caller_stack.pop();
                caller
            })
    }

    /// Return an immutable reference to the contract_context
    pub fn contract_context(&self) -> &ContractContext {
        if let Some(contract_context) = &self.contract_context {
            contract_context
        } else if let Some(contract_context) = &self.contract_context_mut {
            contract_context
        } else {
            unreachable!("contract_context and contract_context_mut are both None")
        }
    }

    /// Return a mutable reference to the contract_context if we are currently
    /// initializing a contract, else, return an error.
    pub fn contract_context_mut(&mut self) -> Result<&mut ContractContext, Error> {
        match &mut self.contract_context_mut {
            Some(contract_context) => Ok(contract_context),
            None => Err(Error::Wasm(WasmError::DefineFunctionCalledInRunMode)),
        }
    }

    pub fn push_to_event_batch(&mut self, event: StacksTransactionEvent) {
        if let Some(batch) = self.global_context.event_batches.last_mut() {
            batch.events.push(event);
        }
    }

    pub fn construct_print_transaction_event(
        contract_id: &QualifiedContractIdentifier,
        value: &Value,
    ) -> StacksTransactionEvent {
        let print_event = SmartContractEventData {
            key: (contract_id.clone(), "print".to_string()),
            value: value.clone(),
        };

        StacksTransactionEvent::SmartContractEvent(print_event)
    }

    pub fn register_print_event(&mut self, value: Value) -> Result<(), Error> {
        let event = Self::construct_print_transaction_event(
            &self.contract_context().contract_identifier,
            &value,
        );

        self.push_to_event_batch(event);
        Ok(())
    }

    pub fn register_stx_transfer_event(
        &mut self,
        sender: PrincipalData,
        recipient: PrincipalData,
        amount: u128,
        memo: BuffData,
    ) -> Result<(), Error> {
        let event_data = STXTransferEventData {
            sender,
            recipient,
            amount,
            memo,
        };
        let event = StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(event_data));

        self.push_to_event_batch(event);
        Ok(())
    }

    pub fn register_stx_burn_event(
        &mut self,
        sender: PrincipalData,
        amount: u128,
    ) -> Result<(), Error> {
        let event_data = STXBurnEventData { sender, amount };
        let event = StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(event_data));

        self.push_to_event_batch(event);
        Ok(())
    }

    pub fn register_nft_transfer_event(
        &mut self,
        sender: PrincipalData,
        recipient: PrincipalData,
        value: Value,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), Error> {
        let event_data = NFTTransferEventData {
            sender,
            recipient,
            asset_identifier,
            value,
        };
        let event = StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(event_data));

        self.push_to_event_batch(event);
        Ok(())
    }

    pub fn register_nft_mint_event(
        &mut self,
        recipient: PrincipalData,
        value: Value,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), Error> {
        let event_data = NFTMintEventData {
            recipient,
            asset_identifier,
            value,
        };
        let event = StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data));

        self.push_to_event_batch(event);
        Ok(())
    }

    pub fn register_nft_burn_event(
        &mut self,
        sender: PrincipalData,
        value: Value,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), Error> {
        let event_data = NFTBurnEventData {
            sender,
            asset_identifier,
            value,
        };
        let event = StacksTransactionEvent::NFTEvent(NFTEventType::NFTBurnEvent(event_data));

        self.push_to_event_batch(event);
        Ok(())
    }

    pub fn register_ft_transfer_event(
        &mut self,
        sender: PrincipalData,
        recipient: PrincipalData,
        amount: u128,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), Error> {
        let event_data = FTTransferEventData {
            sender,
            recipient,
            asset_identifier,
            amount,
        };
        let event = StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data));

        self.push_to_event_batch(event);
        Ok(())
    }

    pub fn register_ft_mint_event(
        &mut self,
        recipient: PrincipalData,
        amount: u128,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), Error> {
        let event_data = FTMintEventData {
            recipient,
            asset_identifier,
            amount,
        };
        let event = StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data));

        self.push_to_event_batch(event);
        Ok(())
    }

    pub fn register_ft_burn_event(
        &mut self,
        sender: PrincipalData,
        amount: u128,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), Error> {
        let event_data = FTBurnEventData {
            sender,
            asset_identifier,
            amount,
        };
        let event = StacksTransactionEvent::FTEvent(FTEventType::FTBurnEvent(event_data));

        self.push_to_event_batch(event);
        Ok(())
    }
}

/// Push a placeholder value for Wasm type `ty` onto the data stack.
fn placeholder_for_type(ty: ValType) -> Val {
    match ty {
        ValType::I32 => Val::I32(0),
        ValType::I64 => Val::I64(0),
        ValType::F32 => Val::F32(0),
        ValType::F64 => Val::F64(0),
        ValType::V128 => Val::V128(0),
        ValType::ExternRef => unimplemented!("ExternRef"),
        ValType::FuncRef => unimplemented!("FuncRef"),
    }
}

/// Initialize a contract, executing all of the top-level expressions and
/// registering all of the definitions in the context. Returns the value
/// returned from the last top-level expression.
pub fn initialize_contract(
    global_context: &mut GlobalContext,
    contract_context: &mut ContractContext,
    sponsor: Option<PrincipalData>,
    contract_analysis: &ContractAnalysis,
) -> Result<Option<Value>, Error> {
    let publisher: PrincipalData = contract_context.contract_identifier.issuer.clone().into();

    let mut call_stack = CallStack::new();
    let init_context = ClarityWasmContext::new_init(
        global_context,
        contract_context,
        &mut call_stack,
        Some(publisher.clone()),
        Some(publisher),
        sponsor.clone(),
        Some(contract_analysis),
    );
    let engine = Engine::default();
    let module = init_context
        .contract_context()
        .with_wasm_module(|wasm_module| {
            Module::from_binary(&engine, wasm_module)
                .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))
        })?;
    let mut store = Store::new(&engine, init_context);
    let mut linker = Linker::new(&engine);

    // Link in the host interface functions.
    link_host_functions(&mut linker)?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))?;

    // Call the `.top-level` function, which contains all top-level expressions
    // from the contract.
    let top_level = instance
        .get_func(&mut store, ".top-level")
        .ok_or(Error::Wasm(WasmError::DefinesNotFound))?;

    // Get the return type of the top-level expressions function
    let ty = top_level.ty(&mut store);
    let mut results_iter = ty.results();
    let mut results = vec![];
    while let Some(result_ty) = results_iter.next() {
        results.push(placeholder_for_type(result_ty));
    }

    top_level
        .call(&mut store, &[], results.as_mut_slice())
        .map_err(|e| Error::Wasm(WasmError::Runtime(e)))?;

    // Save the compiled Wasm module into the contract context
    store.data_mut().contract_context_mut()?.set_wasm_module(
        module
            .serialize()
            .map_err(|e| Error::Wasm(WasmError::WasmCompileFailed(e)))?,
    );

    let return_type = contract_analysis.expressions.last().and_then(|last_expr| {
        contract_analysis
            .type_map
            .as_ref()
            .and_then(|type_map| type_map.get_type(last_expr))
    });

    if let Some(return_type) = return_type {
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;
        wasm_to_clarity_value(return_type, 0, &results, memory, &mut &mut store)
            .map(|(val, _offset)| val)
    } else {
        Ok(None)
    }
}

/// Call a function in the contract.
pub fn call_function<'a, 'b, 'c>(
    function_name: &str,
    args: &[Value],
    global_context: &'a mut GlobalContext<'b>,
    contract_context: &'a ContractContext,
    call_stack: &'a mut CallStack,
    sender: Option<PrincipalData>,
    caller: Option<PrincipalData>,
    sponsor: Option<PrincipalData>,
) -> Result<Value, Error> {
    let context = ClarityWasmContext::new_run(
        global_context,
        contract_context,
        call_stack,
        sender,
        caller,
        sponsor,
        None,
    );

    let func_types = context
        .contract_context()
        .lookup_function(function_name)
        .ok_or(CheckErrors::UndefinedFunction(function_name.to_string()))?;
    let engine = Engine::default();
    let module = context
        .contract_context()
        .with_wasm_module(|wasm_module| unsafe {
            Module::deserialize(&engine, wasm_module)
                .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))
        })?;
    let mut store = Store::new(&engine, context);
    let mut linker = Linker::new(&engine);

    // Link in the host interface functions.
    link_host_functions(&mut linker)?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))?;

    // Call the specified function
    let func = instance
        .get_func(&mut store, function_name)
        .ok_or(CheckErrors::UndefinedFunction(function_name.to_string()))?;

    // Access the global stack pointer from the instance
    let stack_pointer = instance
        .get_global(&mut store, "stack-pointer")
        .ok_or(Error::Wasm(WasmError::StackPointerNotFound))?;
    let mut offset = stack_pointer
        .get(&mut store)
        .i32()
        .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

    // Determine how much space is needed for arguments
    let mut arg_size = 0;
    for arg in func_types.get_arg_types() {
        arg_size += get_type_size(arg);
    }
    let mut in_mem_offset = offset + arg_size;

    // Convert the args into wasmtime values
    let mut wasm_args = vec![];
    for arg in args {
        let (arg_vec, new_offset, new_in_mem_offset) =
            pass_argument_to_wasm(memory, &mut store, arg, offset, in_mem_offset)?;
        wasm_args.extend(arg_vec);
        offset = new_offset;
        in_mem_offset = new_in_mem_offset;
    }

    // Reserve stack space for the return value, if necessary.
    let return_type = store
        .data()
        .contract_context()
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
        .set(&mut store, Val::I32(offset))
        .map_err(|e| Error::Wasm(WasmError::Runtime(e)))?;

    // Call the function
    func.call(&mut store, &wasm_args, &mut results)
        .map_err(|e| {
            // TODO: If the root cause is a clarity error, we should be able to return that,
            //       but it is not cloneable, so we can't return it directly.
            //       If the root cause is a trap from our Wasm code, then we need to translate
            //       it into a Clarity error.
            //       See issue stacks-network/clarity-wasm#104
            // if let Some(vm_error) = e.root_cause().downcast_ref::<crate::vm::errors::Error>() {
            //     vm_error.clone()
            // } else {
            //     Error::Wasm(WasmError::Runtime(e))
            // }
            Error::Wasm(WasmError::Runtime(e))
        })?;

    // If the function returns a value, translate it into a Clarity `Value`
    wasm_to_clarity_value(&return_type, 0, &results, memory, &mut &mut store)
        .map(|(val, _offset)| val)
        .and_then(|option_value| {
            option_value.ok_or_else(|| Error::Wasm(WasmError::ExpectedReturnValue))
        })
}

// Bytes for principal version
pub const PRINCIPAL_VERSION_BYTES: usize = 1;
// Number of bytes in principal hash
pub const PRINCIPAL_HASH_BYTES: usize = 20;
// Standard principal version + hash
pub const PRINCIPAL_BYTES: usize = PRINCIPAL_VERSION_BYTES + PRINCIPAL_HASH_BYTES;
// Number of bytes used to store the length of the contract name
pub const CONTRACT_NAME_LENGTH_BYTES: usize = 4;
// 1 byte for version, 20 bytes for hash, 4 bytes for contract name length (0)
pub const STANDARD_PRINCIPAL_BYTES: usize = PRINCIPAL_BYTES + CONTRACT_NAME_LENGTH_BYTES;
// Max length of a contract name
pub const CONTRACT_NAME_MAX_LENGTH: usize = 128;
// Standard principal, but at most 128 character function name
pub const PRINCIPAL_BYTES_MAX: usize = STANDARD_PRINCIPAL_BYTES + CONTRACT_NAME_MAX_LENGTH;

/// Return the number of bytes required to representation of a value of the
/// type `ty`. For in-memory types, this is just the size of the offset and
/// length. For non-in-memory types, this is the size of the value itself.
pub fn get_type_size(ty: &TypeSignature) -> i32 {
    match ty {
        TypeSignature::IntType | TypeSignature::UIntType => 16, // low: i64, high: i64
        TypeSignature::BoolType => 4,                           // i32
        TypeSignature::PrincipalType | TypeSignature::SequenceType(_) => 8, // offset: i32, length: i32
        TypeSignature::OptionalType(inner) => 4 + get_type_size(inner), // indicator: i32, value: inner
        TypeSignature::TupleType(tuple_ty) => {
            let mut size = 0;
            for inner_type in tuple_ty.get_type_map().values() {
                size += get_type_size(inner_type);
            }
            size
        }
        TypeSignature::ResponseType(inner_types) => {
            // indicator: i32, ok_val: inner_types.0, err_val: inner_types.1
            4 + get_type_size(&inner_types.0) + get_type_size(&inner_types.1)
        }
        TypeSignature::NoType => 4, // i32
        TypeSignature::CallableType(_)
        | TypeSignature::ListUnionType(_)
        | TypeSignature::TraitReferenceType(_) => unreachable!("not a value type"),
    }
}

/// Return the number of bytes required to store a value of the type `ty`.
pub fn get_type_in_memory_size(ty: &TypeSignature, include_repr: bool) -> i32 {
    match ty {
        TypeSignature::IntType | TypeSignature::UIntType => 16, // i64_low + i64_high
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(length))) => {
            let mut size = u32::from(length) as i32;
            if include_repr {
                size += 8; // offset + length
            }
            size
        }
        TypeSignature::PrincipalType | TypeSignature::CallableType(_) => {
            // Standard principal is a 1 byte version and a 20 byte Hash160.
            // Then there is an int32 for the contract name length, followed by
            // the contract name, which has a max length of 128.
            let mut size = PRINCIPAL_BYTES_MAX as i32;
            if include_repr {
                size += 8; // offset + length
            }
            size
        }
        TypeSignature::OptionalType(inner) => 4 + get_type_in_memory_size(inner, true),
        TypeSignature::SequenceType(SequenceSubtype::ListType(list_data)) => {
            let mut size =
                list_data.get_max_len() as i32 * get_type_size(list_data.get_list_item_type());
            if include_repr {
                size += 8; // offset + length
            }
            size
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(length)) => {
            u32::from(length) as i32
        }
        TypeSignature::SequenceType(_) => todo!(),
        TypeSignature::NoType => 4,   // i32
        TypeSignature::BoolType => 4, // i32
        TypeSignature::TupleType(tuple_ty) => {
            let mut size = 0;
            for inner_type in tuple_ty.get_type_map().values() {
                size += get_type_in_memory_size(inner_type, true);
            }
            size
        }
        TypeSignature::ResponseType(res_types) => {
            // indicator: i32, ok_val: inner_types.0, err_val: inner_types.1
            4 + get_type_in_memory_size(&res_types.0, true)
                + get_type_in_memory_size(&res_types.1, true)
        }
        TypeSignature::ListUnionType(_) => todo!(),
        TypeSignature::TraitReferenceType(_) => todo!(),
    }
}

/// Return true if the value of the given type stays in memory, and false if
/// it is stored on the data stack.
pub fn is_in_memory_type(ty: &TypeSignature) -> bool {
    match ty {
        TypeSignature::NoType
        | TypeSignature::IntType
        | TypeSignature::UIntType
        | TypeSignature::BoolType
        | TypeSignature::TupleType(_)
        | TypeSignature::OptionalType(_)
        | TypeSignature::ResponseType(_) => false,
        TypeSignature::SequenceType(_) | TypeSignature::PrincipalType => true,
        TypeSignature::CallableType(_)
        | TypeSignature::ListUnionType(_)
        | TypeSignature::TraitReferenceType(_) => unreachable!("not a value type"),
    }
}

fn clar2wasm_ty(ty: &TypeSignature) -> Vec<ValType> {
    match ty {
        TypeSignature::NoType => vec![ValType::I32], // TODO: can this just be empty?
        TypeSignature::IntType => vec![ValType::I64, ValType::I64],
        TypeSignature::UIntType => vec![ValType::I64, ValType::I64],
        TypeSignature::ResponseType(inner_types) => {
            let mut types = vec![ValType::I32];
            types.extend(clar2wasm_ty(&inner_types.0));
            types.extend(clar2wasm_ty(&inner_types.1));
            types
        }
        TypeSignature::SequenceType(_) => vec![
            ValType::I32, // offset
            ValType::I32, // length
        ],
        TypeSignature::BoolType => vec![ValType::I32],
        TypeSignature::PrincipalType | TypeSignature::CallableType(_) => vec![
            ValType::I32, // offset
            ValType::I32, // length
        ],
        TypeSignature::OptionalType(inner_ty) => {
            let mut types = vec![ValType::I32];
            types.extend(clar2wasm_ty(inner_ty));
            types
        }
        TypeSignature::TupleType(inner_types) => {
            let mut types = vec![];
            for inner_type in inner_types.get_type_map().values() {
                types.extend(clar2wasm_ty(inner_type));
            }
            types
        }
        _ => unimplemented!("{:?}", ty),
    }
}

/// Read bytes from the WASM memory at `offset` with `length`
fn read_bytes_from_wasm(
    memory: Memory,
    store: &mut impl AsContextMut,
    offset: i32,
    length: i32,
) -> Result<Vec<u8>, Error> {
    let mut buffer: Vec<u8> = vec![0; length as usize];
    memory
        .read(store, offset as usize, &mut buffer)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
    Ok(buffer)
}

/// Read an identifier (string) from the WASM memory at `offset` with `length`.
fn read_identifier_from_wasm(
    memory: Memory,
    store: &mut impl AsContextMut,
    offset: i32,
    length: i32,
) -> Result<String, Error> {
    let buffer = read_bytes_from_wasm(memory, store, offset, length)?;
    String::from_utf8(buffer).map_err(|e| Error::Wasm(WasmError::UnableToReadIdentifier(e)))
}

/// Read a value from the WASM memory at `offset` with `length` given the
/// provided Clarity `TypeSignature`. In-memory values require one extra level
/// of indirection, so this function will read the offset and length from the
/// memory, then read the actual value.
fn read_from_wasm_indirect(
    memory: Memory,
    mut store: &mut impl AsContextMut,
    ty: &TypeSignature,
    mut offset: i32,
) -> Result<Value, Error> {
    let mut length = get_type_size(ty);

    // For in-memory types, first read the offset and length from the memory,
    // then read the actual value.
    if is_in_memory_type(ty) {
        let mut buffer: [u8; 4] = [0; 4];
        memory
            .read(&mut store, offset as usize, &mut buffer)
            .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
        let indirect_offset = i32::from_le_bytes(buffer);
        memory
            .read(&mut store, (offset + 4) as usize, &mut buffer)
            .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
        length = i32::from_le_bytes(buffer);
        offset = indirect_offset;
    };

    read_from_wasm(memory, store, ty, offset, length)
}

/// Read a value from the WASM memory at `offset` with `length`, given the
/// provided Clarity `TypeSignature`.
fn read_from_wasm(
    memory: Memory,
    mut store: &mut impl AsContextMut,
    ty: &TypeSignature,
    offset: i32,
    length: i32,
) -> Result<Value, Error> {
    match ty {
        TypeSignature::UIntType => {
            debug_assert!(
                length == 16,
                "expected uint length to be 16 bytes, found {length}"
            );
            let mut buffer: [u8; 8] = [0; 8];
            memory
                .read(&mut store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let low = u64::from_le_bytes(buffer) as u128;
            memory
                .read(store, (offset + 8) as usize, &mut buffer)
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
                .read(&mut store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let low = u64::from_le_bytes(buffer) as u128;
            memory
                .read(store, (offset + 8) as usize, &mut buffer)
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
                .read(store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            Value::string_ascii_from_bytes(buffer)
        }
        TypeSignature::PrincipalType => {
            debug_assert!(
                length >= STANDARD_PRINCIPAL_BYTES as i32 && length <= PRINCIPAL_BYTES_MAX as i32
            );
            let mut current_offset = offset as usize;
            let mut version: [u8; PRINCIPAL_VERSION_BYTES] = [0; PRINCIPAL_VERSION_BYTES];
            let mut hash: [u8; PRINCIPAL_HASH_BYTES] = [0; PRINCIPAL_HASH_BYTES];
            memory
                .read(&mut store, current_offset, &mut version)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += PRINCIPAL_VERSION_BYTES;
            memory
                .read(&mut store, current_offset, &mut hash)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += PRINCIPAL_HASH_BYTES;
            let principal = StandardPrincipalData(version[0], hash);
            let mut contract_length_buf: [u8; CONTRACT_NAME_LENGTH_BYTES] =
                [0; CONTRACT_NAME_LENGTH_BYTES];
            memory
                .read(&mut store, current_offset, &mut contract_length_buf)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            current_offset += CONTRACT_NAME_LENGTH_BYTES;
            let contract_length = u32::from_le_bytes(contract_length_buf);
            if contract_length == 0 {
                Ok(Value::Principal(principal.into()))
            } else {
                let mut contract_name: Vec<u8> = vec![0; contract_length as usize];
                memory
                    .read(store, current_offset, &mut contract_name)
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
            let mut buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            Value::buff_from(buffer)
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(list)) => {
            let elem_ty = list.get_list_item_type();
            let elem_length = get_type_size(elem_ty);
            let end = offset + length;
            let mut buffer: Vec<Value> = Vec::new();
            let mut current_offset = offset;
            while current_offset < end {
                let elem = read_from_wasm_indirect(memory, store, elem_ty, current_offset)?;
                buffer.push(elem);
                current_offset += elem_length;
            }
            Value::list_from(buffer)
        }
        TypeSignature::BoolType => {
            debug_assert!(
                length == 4,
                "expected bool length to be 4 bytes, found {length}"
            );
            let mut buffer: [u8; 4] = [0; 4];
            memory
                .read(&mut store, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            let bool_val = u32::from_le_bytes(buffer);
            Ok(Value::Bool(bool_val != 0))
        }
        TypeSignature::ResponseType(_r) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::CallableType(_subtype) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ListUnionType(_subtypes) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::NoType => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::OptionalType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TraitReferenceType(_trait_id) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TupleType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
    }
}

fn value_as_bool(value: &Value) -> Result<bool, Error> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
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

fn value_as_buffer(value: Value) -> Result<BuffData, Error> {
    match value {
        Value::Sequence(SequenceData::Buffer(buffdata)) => Ok(buffdata),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

fn value_as_optional(value: &Value) -> Result<&OptionalData, Error> {
    match value {
        Value::Optional(opt_data) => Ok(opt_data),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

fn value_as_response(value: &Value) -> Result<&ResponseData, Error> {
    match value {
        Value::Response(res_data) => Ok(res_data),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

fn value_as_string_ascii(value: Value) -> Result<ASCIIData, Error> {
    match value {
        Value::Sequence(SequenceData::String(CharType::ASCII(string_data))) => Ok(string_data),
        _ => Err(Error::Wasm(WasmError::ValueTypeMismatch)),
    }
}

/// Write a value to the Wasm memory at `offset` given the provided Clarity
/// `TypeSignature`. If the value is an in-memory type, then it will be written
/// to the memory at `in_mem_offset`, and if `include_repr` is true, the offset
/// and length of the value will be written to the memory at `offset`.
/// Returns the number of bytes written at `offset` and at `in_mem_offset`.
fn write_to_wasm(
    mut store: impl AsContextMut,
    memory: Memory,
    ty: &TypeSignature,
    offset: i32,
    in_mem_offset: i32,
    value: &Value,
    include_repr: bool,
) -> Result<(i32, i32), Error> {
    match ty {
        TypeSignature::IntType => {
            let mut buffer: [u8; 8] = [0; 8];
            let i = value_as_i128(&value)?;
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            buffer.copy_from_slice(&low.to_le_bytes());
            memory
                .write(&mut store, offset as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            buffer.copy_from_slice(&high.to_le_bytes());
            memory
                .write(&mut store, (offset + 8) as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok((16, 0))
        }
        TypeSignature::UIntType => {
            let mut buffer: [u8; 8] = [0; 8];
            let i = value_as_u128(&value)?;
            let high = (i >> 64) as u64;
            let low = (i & 0xffff_ffff_ffff_ffff) as u64;
            buffer.copy_from_slice(&low.to_le_bytes());
            memory
                .write(&mut store, offset as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            buffer.copy_from_slice(&high.to_le_bytes());
            memory
                .write(&mut store, (offset + 8) as usize, &buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok((16, 0))
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_length)) => {
            let buffdata = value_as_buffer(value.clone())?;
            let mut written = 0;
            let mut in_mem_written = 0;

            // Write the value to `in_mem_offset`
            memory
                .write(
                    &mut store,
                    (in_mem_offset + in_mem_written) as usize,
                    &buffdata.data,
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            in_mem_written += buffdata.data.len() as i32;

            if include_repr {
                // Write the representation (offset and length) of the value to
                // `offset`.
                let offset_buffer = (in_mem_offset as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset) as usize, &offset_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
                let len_buffer = (in_mem_written as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset + written) as usize, &len_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
            }

            Ok((written, in_mem_written))
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(_length))) => {
            let string = value_as_string_ascii(value.clone())?;
            let mut written = 0;
            let mut in_mem_written = 0;

            // Write the value to `in_mem_offset`
            memory
                .write(
                    &mut store,
                    (in_mem_offset + in_mem_written) as usize,
                    &string.data,
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            in_mem_written += string.data.len() as i32;

            if include_repr {
                // Write the representation (offset and length) of the value to
                // `offset`.
                let offset_buffer = (in_mem_offset as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset) as usize, &offset_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
                let len_buffer = (in_mem_written as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset + written) as usize, &len_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
            }

            Ok((written, in_mem_written))
        }
        TypeSignature::SequenceType(_) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::ResponseType(inner_types) => {
            let mut written = 0;
            let mut in_mem_written = 0;
            let res = value_as_response(value)?;
            let indicator = if res.committed { 1i32 } else { 0i32 };
            let indicator_bytes = indicator.to_le_bytes();
            memory
                .write(&mut store, (offset) as usize, &indicator_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            written += 4;
            if res.committed {
                let (new_written, new_in_mem_written) = write_to_wasm(
                    store,
                    memory,
                    &inner_types.0,
                    offset + written,
                    in_mem_offset,
                    &res.data,
                    true,
                )?;
                written += new_written;
                in_mem_written += new_in_mem_written;

                // Skip space for the err value
                written += get_type_size(&inner_types.1);
            } else {
                // Skip space for the ok value
                written += get_type_size(&inner_types.0);

                let (new_written, new_in_mem_written) = write_to_wasm(
                    store,
                    memory,
                    &inner_types.1,
                    offset + written,
                    in_mem_offset,
                    &res.data,
                    true,
                )?;
                written += new_written;
                in_mem_written += new_in_mem_written;
            }
            Ok((written, in_mem_written))
        }
        TypeSignature::BoolType => {
            let bool_val = value_as_bool(&value)?;
            let val = if bool_val { 1u32 } else { 0u32 };
            let val_bytes = val.to_le_bytes();
            memory
                .write(&mut store, (offset) as usize, &val_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok((4, 0))
        }
        TypeSignature::NoType => {
            let val_bytes = [0u8; 4];
            memory
                .write(&mut store, (offset) as usize, &val_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            Ok((4, 0))
        }
        TypeSignature::OptionalType(inner_ty) => {
            let mut written = 0;
            let mut in_mem_written = 0;
            let opt_data = value_as_optional(value)?;
            let indicator = if opt_data.data.is_some() { 1i32 } else { 0i32 };
            let indicator_bytes = indicator.to_le_bytes();
            memory
                .write(&mut store, (offset) as usize, &indicator_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            written += 4;
            if let Some(inner) = opt_data.data.as_ref() {
                let (new_written, new_in_mem_written) = write_to_wasm(
                    store,
                    memory,
                    inner_ty,
                    offset + written,
                    in_mem_offset,
                    inner,
                    true,
                )?;
                written += new_written;
                in_mem_written += new_in_mem_written;
            }
            Ok((written, in_mem_written))
        }
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
            let mut in_mem_written = 0;

            // Write the value to in_mem_offset
            memory
                .write(
                    &mut store,
                    (in_mem_offset + in_mem_written) as usize,
                    &[standard.0],
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            in_mem_written += 1;
            memory
                .write(
                    &mut store,
                    (in_mem_offset + in_mem_written) as usize,
                    &standard.1,
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            in_mem_written += standard.1.len() as i32;
            if !contract_name.is_empty() {
                let len_buffer = (contract_name.len() as i32).to_le_bytes();
                memory
                    .write(
                        &mut store,
                        (in_mem_offset + in_mem_written) as usize,
                        &len_buffer,
                    )
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                in_mem_written += 4;
                let bytes = contract_name.as_bytes();
                memory
                    .write(&mut store, (in_mem_offset + in_mem_written) as usize, bytes)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                in_mem_written += bytes.len() as i32;
            } else {
                let len_buffer = (0i32).to_le_bytes();
                memory
                    .write(
                        &mut store,
                        (in_mem_offset + in_mem_written) as usize,
                        &len_buffer,
                    )
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                in_mem_written += 4;
            }

            if include_repr {
                // Write the representation (offset and length of the value) to the
                // offset
                let offset_buffer = (in_mem_offset as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset) as usize, &offset_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
                let len_buffer = (in_mem_written as i32).to_le_bytes();
                memory
                    .write(&mut store, (offset + written) as usize, &len_buffer)
                    .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
                written += 4;
            }

            Ok((written, in_mem_written))
        }
        TypeSignature::TraitReferenceType(_trait_id) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::TupleType(_type_sig) => todo!("type not yet implemented: {:?}", ty),
        TypeSignature::CallableType(_) | TypeSignature::ListUnionType(_) => {
            unreachable!("not a value type")
        }
    }
}

/// Convert a Clarity `Value` into one or more Wasm `Val`. If this value
/// requires writing into the Wasm memory, write it to the provided `offset`.
/// Return a vector of `Val`s that can be passed to a Wasm function, and the
/// two offsets, adjusted to the next available memory location.
fn pass_argument_to_wasm(
    memory: Memory,
    mut store: impl AsContextMut,
    value: &Value,
    offset: i32,
    in_mem_offset: i32,
) -> Result<(Vec<Val>, i32, i32), Error> {
    match value {
        Value::UInt(n) => {
            let high = (n >> 64) as u64;
            let low = (n & 0xffff_ffff_ffff_ffff) as u64;
            let buffer = vec![Val::I64(low as i64), Val::I64(high as i64)];
            Ok((buffer, offset, in_mem_offset))
        }
        Value::Int(n) => {
            let high = (n >> 64) as u64;
            let low = (n & 0xffff_ffff_ffff_ffff) as u64;
            let buffer = vec![Val::I64(low as i64), Val::I64(high as i64)];
            Ok((buffer, offset, in_mem_offset))
        }
        Value::Bool(b) => Ok((
            vec![Val::I32(if *b { 1 } else { 0 })],
            offset,
            in_mem_offset,
        )),
        Value::Optional(o) => {
            let mut buffer = vec![Val::I32(if o.data.is_some() { 1 } else { 0 })];
            let (inner, new_offset, new_in_mem_offset) = pass_argument_to_wasm(
                memory,
                store,
                o.data
                    .as_ref()
                    .map_or(&Value::none(), |boxed_value| &boxed_value),
                offset,
                in_mem_offset,
            )?;
            buffer.extend(inner);
            Ok((buffer, new_offset, new_in_mem_offset))
        }
        Value::Response(r) => {
            let mut buffer = vec![Val::I32(if r.committed { 1 } else { 0 })];
            let (inner, new_offset, new_in_mem_offset) = if r.committed {
                pass_argument_to_wasm(memory, store, &r.data, offset, in_mem_offset)?
            } else {
                pass_argument_to_wasm(memory, store, &r.data, offset, in_mem_offset)?
            };
            buffer.extend(inner);
            Ok((buffer, new_offset, new_in_mem_offset))
        }
        Value::Sequence(SequenceData::String(CharType::ASCII(s))) => {
            // For a string, write the bytes into the memory, then pass the
            // offset and length to the Wasm function.
            let buffer = vec![Val::I32(in_mem_offset), Val::I32(s.data.len() as i32)];
            memory
                .write(
                    store.borrow_mut(),
                    in_mem_offset as usize,
                    s.data.as_slice(),
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            let adjusted_in_mem_offset = in_mem_offset + s.data.len() as i32;
            Ok((buffer, offset, adjusted_in_mem_offset))
        }
        Value::Sequence(SequenceData::String(CharType::UTF8(_s))) => {
            todo!("Value type not yet implemented: {:?}", value)
        }
        Value::Sequence(SequenceData::Buffer(b)) => {
            // For a buffer, write the bytes into the memory, then pass the
            // offset and length to the Wasm function.
            let buffer = vec![Val::I32(in_mem_offset), Val::I32(b.data.len() as i32)];
            memory
                .write(
                    store.borrow_mut(),
                    in_mem_offset as usize,
                    b.data.as_slice(),
                )
                .map_err(|e| Error::Wasm(WasmError::UnableToWriteMemory(e.into())))?;
            let adjusted_in_mem_offset = in_mem_offset + b.data.len() as i32;
            Ok((buffer, offset, adjusted_in_mem_offset))
        }
        Value::Sequence(SequenceData::List(l)) => {
            let mut buffer = vec![Val::I32(offset)];
            let mut written = 0;
            let mut in_mem_written = 0;
            for item in &l.data {
                let (len, in_mem_len) = write_to_wasm(
                    &mut store,
                    memory,
                    l.type_signature.get_list_item_type(),
                    offset + written,
                    in_mem_offset + in_mem_written,
                    item,
                    true,
                )?;
                written += len;
                in_mem_written += in_mem_len;
            }
            buffer.push(Val::I32(written));
            Ok((buffer, offset + written, in_mem_offset + in_mem_written))
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
) -> Result<(Vec<Val>, i32), Error> {
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
        TypeSignature::SequenceType(_)
        | TypeSignature::PrincipalType
        | TypeSignature::CallableType(_) => {
            // All in-memory types return an offset and length.˝
            let length = get_type_in_memory_size(return_type, false);

            // Return values will be offset and length
            Ok((vec![Val::I32(0), Val::I32(0)], offset + length))
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
        TypeSignature::ListUnionType(_) | TypeSignature::TraitReferenceType(_) => {
            unreachable!("not a valid return type");
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
    mut store: &mut impl AsContextMut,
) -> Result<(Option<Value>, usize), Error> {
    match type_sig {
        TypeSignature::IntType => {
            let lower = buffer[value_index]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let upper = buffer[value_index + 1]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            Ok((
                Some(Value::Int(((upper as i128) << 64) | (lower as u64) as i128)),
                2,
            ))
        }
        TypeSignature::UIntType => {
            let lower = buffer[value_index]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let upper = buffer[value_index + 1]
                .i64()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            Ok((
                Some(Value::UInt(
                    ((upper as u128) << 64) | (lower as u64) as u128,
                )),
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
            let value_types = clar2wasm_ty(optional);
            Ok((
                if buffer[value_index]
                    .i32()
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?
                    == 1
                {
                    let (value, _) =
                        wasm_to_clarity_value(optional, value_index + 1, buffer, memory, store)?;
                    Some(Value::some(value.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineType,
                    ))?)?)
                } else {
                    Some(Value::none())
                },
                1 + value_types.len(),
            ))
        }
        TypeSignature::ResponseType(response) => {
            let ok_types = clar2wasm_ty(&response.0);
            let err_types = clar2wasm_ty(&response.1);

            Ok((
                if buffer[value_index]
                    .i32()
                    .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?
                    == 1
                {
                    let (ok, _) =
                        wasm_to_clarity_value(&response.0, value_index + 1, buffer, memory, store)?;
                    Some(Value::okay(ok.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineResponseOkType,
                    ))?)?)
                } else {
                    let (err, _) = wasm_to_clarity_value(
                        &response.1,
                        value_index + 1 + ok_types.len(),
                        buffer,
                        memory,
                        store,
                    )?;
                    Some(Value::error(err.ok_or(Error::Unchecked(
                        CheckErrors::CouldNotDetermineResponseErrType,
                    ))?)?)
                },
                1 + ok_types.len() + err_types.len(),
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
                .read(store, offset as usize, &mut string_buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            Ok((Some(Value::string_ascii_from_bytes(string_buffer)?), 2))
        }
        // A `NoType` will be a dummy value that should not be used.
        TypeSignature::NoType => Ok((None, 1)),
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_s))) => {
            todo!("Wasm value type not implemented: {:?}", type_sig)
        }
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_buffer_length)) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let length = buffer[value_index + 1]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut buff: Vec<u8> = vec![0; length as usize];
            memory
                .read(store, offset as usize, &mut buff)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            Ok((Some(Value::buff_from(buff)?), 2))
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(_)) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let length = buffer[value_index + 1]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;

            let value = read_from_wasm(memory, store, type_sig, offset, length)?;
            Ok((Some(value), 2))
        }
        TypeSignature::PrincipalType | TypeSignature::CallableType(_) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut principal_bytes: [u8; 1 + PRINCIPAL_HASH_BYTES] = [0; 1 + PRINCIPAL_HASH_BYTES];
            memory
                .read(&mut store, offset as usize, &mut principal_bytes)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            let mut buffer: [u8; CONTRACT_NAME_LENGTH_BYTES] = [0; CONTRACT_NAME_LENGTH_BYTES];
            memory
                .read(&mut store, offset as usize + 21, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            let standard =
                StandardPrincipalData(principal_bytes[0], principal_bytes[1..].try_into().unwrap());
            let contract_name_length = i32::from_le_bytes(buffer);
            if contract_name_length == 0 {
                Ok((
                    Some(Value::Principal(PrincipalData::Standard(standard))),
                    STANDARD_PRINCIPAL_BYTES,
                ))
            } else {
                let mut contract_name: Vec<u8> = vec![0; contract_name_length as usize];
                memory
                    .read(
                        store,
                        (offset + STANDARD_PRINCIPAL_BYTES as i32) as usize,
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
                    STANDARD_PRINCIPAL_BYTES + contract_name_length as usize,
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
    }
}

/// Link the host interface functions for into the Wasm module.
fn link_host_functions(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    link_define_function_fn(linker)?;
    link_define_variable_fn(linker)?;
    link_define_ft_fn(linker)?;
    link_define_nft_fn(linker)?;
    link_define_map_fn(linker)?;
    link_define_trait_fn(linker)?;
    link_impl_trait_fn(linker)?;

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
    link_stx_burn_fn(linker)?;
    link_stx_transfer_fn(linker)?;
    link_ft_get_supply_fn(linker)?;
    link_ft_get_balance_fn(linker)?;
    link_ft_burn_fn(linker)?;
    link_ft_mint_fn(linker)?;
    link_ft_transfer_fn(linker)?;
    link_nft_get_owner_fn(linker)?;
    link_nft_burn_fn(linker)?;
    link_nft_mint_fn(linker)?;
    link_nft_transfer_fn(linker)?;
    link_map_get_fn(linker)?;
    link_map_set_fn(linker)?;
    link_map_insert_fn(linker)?;
    link_map_delete_fn(linker)?;
    link_get_block_info_fn(linker)?;
    link_get_burn_block_info_fn(linker)?;
    link_contract_call_fn(linker)?;
    link_print_fn(linker)?;

    link_log(linker)
}

/// Link host interface function, `define_variable`, into the Wasm module.
/// This function is called for all variable definitions (`define-data-var`).
fn link_define_variable_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_variable",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             value_offset: i32,
             value_length: i32| {
                // TODO: Include this cost
                // runtime_cost(ClarityCostFunction::CreateVar, global_context, value_type.size())?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Read the variable name string from the memory
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                // Retrieve the type of this variable
                let value_type = caller
                    .data()
                    .contract_analysis
                    .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
                    .get_persisted_variable_type(name.as_str())
                    .ok_or(Error::Unchecked(CheckErrors::DefineVariableBadSignature))?
                    .clone();

                let contract = caller.data().contract_context().contract_identifier.clone();

                // Read the initial value from the memory
                let value =
                    read_from_wasm(memory, &mut caller, &value_type, value_offset, value_length)?;

                caller
                    .data_mut()
                    .contract_context_mut()?
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
                    .contract_context_mut()?
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

fn link_define_ft_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_ft",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             supply_indicator: i32,
             supply_lo: i64,
             supply_hi: i64| {
                // runtime_cost(ClarityCostFunction::CreateFt, global_context, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier = caller
                    .data_mut()
                    .contract_context()
                    .contract_identifier
                    .clone();

                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let cname = ClarityName::try_from(name.clone())?;

                let total_supply = if supply_indicator == 1 {
                    Some(((supply_hi as u128) << 64) | supply_lo as u128)
                } else {
                    None
                };

                caller
                    .data_mut()
                    .contract_context_mut()?
                    .persisted_names
                    .insert(cname.clone());

                caller
                    .data_mut()
                    .global_context
                    .add_memory(
                        TypeSignature::UIntType
                            .type_size()
                            .expect("type size should be realizable")
                            as u64,
                    )
                    .map_err(|e| Error::from(e))?;
                let data_type = caller
                    .data_mut()
                    .global_context
                    .database
                    .create_fungible_token(&contract_identifier, &name, &total_supply);

                caller
                    .data_mut()
                    .contract_context_mut()?
                    .meta_ft
                    .insert(cname, data_type);

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_ft".to_string(),
                e,
            ))
        })
}

fn link_define_nft_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_nft",
            |mut caller: Caller<'_, ClarityWasmContext>, name_offset: i32, name_length: i32| {
                // runtime_cost(ClarityCostFunction::CreateNft, global_context, asset_type.size())?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier = caller
                    .data_mut()
                    .contract_context()
                    .contract_identifier
                    .clone();

                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let cname = ClarityName::try_from(name.clone())?;

                // Get the type of this NFT from the contract analysis
                let asset_type = caller
                    .data()
                    .contract_analysis
                    .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
                    .non_fungible_tokens
                    .get(&cname)
                    .ok_or(Error::Unchecked(CheckErrors::DefineNFTBadSignature))?;

                caller
                    .data_mut()
                    .contract_context_mut()?
                    .persisted_names
                    .insert(cname.clone());

                caller
                    .data_mut()
                    .global_context
                    .add_memory(
                        asset_type
                            .type_size()
                            .expect("type size should be realizable")
                            as u64,
                    )
                    .map_err(|e| Error::from(e))?;

                let data_type = caller
                    .data_mut()
                    .global_context
                    .database
                    .create_non_fungible_token(&contract_identifier, &name, &asset_type);

                caller
                    .data_mut()
                    .contract_context_mut()?
                    .meta_nft
                    .insert(cname, data_type);

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_nft".to_string(),
                e,
            ))
        })
}

fn link_define_map_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_map",
            |mut caller: Caller<'_, ClarityWasmContext>, name_offset: i32, name_length: i32| {
                // runtime_cost(
                //     ClarityCostFunction::CreateMap,
                //     global_context,
                //     u64::from(key_type.size()).cost_overflow_add(u64::from(value_type.size()))?,
                // )?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier = caller
                    .data_mut()
                    .contract_context()
                    .contract_identifier
                    .clone();

                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let cname = ClarityName::try_from(name.clone())?;

                let (key_type, value_type) = caller
                    .data()
                    .contract_analysis
                    .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
                    .get_map_type(&name)
                    .ok_or(Error::Unchecked(CheckErrors::BadMapTypeDefinition))?;

                caller
                    .data_mut()
                    .contract_context_mut()?
                    .persisted_names
                    .insert(cname.clone());

                caller
                    .data_mut()
                    .global_context
                    .add_memory(
                        key_type
                            .type_size()
                            .expect("type size should be realizable")
                            as u64,
                    )
                    .map_err(|e| Error::from(e))?;
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

                let data_type = caller.data_mut().global_context.database.create_map(
                    &contract_identifier,
                    &name,
                    key_type.clone(),
                    value_type.clone(),
                );

                caller
                    .data_mut()
                    .contract_context_mut()?
                    .meta_data_map
                    .insert(cname, data_type);

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_map".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `define_function`, into the Wasm module.
/// This function is called for all function definitions.
fn link_define_function_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_function",
            |mut caller: Caller<'_, ClarityWasmContext>,
             kind: i32,
             name_offset: i32,
             name_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Read the variable name string from the memory
                let function_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let function_cname = ClarityName::try_from(function_name.clone())?;

                // Retrieve the kind of function
                let (define_type, function_type) = match kind {
                    0 => (
                        DefineType::ReadOnly,
                        caller
                            .data()
                            .contract_analysis
                            .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
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
                            .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
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
                            .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
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
                        .contract_context()
                        .contract_identifier
                        .to_string(),
                    Some(fixed_type.returns.clone()),
                );

                // Insert this function into the context
                caller
                    .data_mut()
                    .contract_context_mut()?
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

fn link_define_trait_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_trait",
            |mut caller: Caller<'_, ClarityWasmContext>, name_offset: i32, name_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let cname = ClarityName::try_from(name.clone())?;

                let trait_def = caller
                    .data()
                    .contract_analysis
                    .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
                    .get_defined_trait(name.as_str())
                    .ok_or(Error::Unchecked(CheckErrors::DefineTraitBadSignature))?;

                caller
                    .data_mut()
                    .contract_context_mut()?
                    .defined_traits
                    .insert(cname, trait_def.clone());

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_map".to_string(),
                e,
            ))
        })
}

fn link_impl_trait_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "impl_trait",
            |mut caller: Caller<'_, ClarityWasmContext>, name_offset: i32, name_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let trait_id_string =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let trait_id = TraitIdentifier::parse_fully_qualified(trait_id_string.as_str())?;

                caller
                    .data_mut()
                    .contract_context_mut()?
                    .implemented_traits
                    .insert(trait_id);

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "define_map".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `get_variable`, into the Wasm module.
/// This function is called for all variable lookups (`var-get`).
fn link_get_variable_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "get_variable",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             return_offset: i32,
             _return_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the variable name for this identifier
                let var_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let contract = caller.data().contract_context().contract_identifier.clone();

                // Retrieve the metadata for this variable
                let data_types = caller
                    .data()
                    .contract_context()
                    .meta_data_var
                    .get(var_name.as_str())
                    .ok_or(CheckErrors::NoSuchDataVariable(var_name.to_string()))?
                    .clone();

                let result = caller
                    .data_mut()
                    .global_context
                    .database
                    .lookup_variable_with_size(&contract, var_name.as_str(), &data_types);

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
                    return_offset + get_type_size(&data_types.value_type),
                    &value,
                    true,
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
fn link_set_variable_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "set_variable",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             value_offset: i32,
             value_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the variable name for this identifier
                let var_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let contract = caller.data().contract_context().contract_identifier.clone();

                let data_types = caller
                    .data()
                    .contract_context()
                    .meta_data_var
                    .get(var_name.as_str())
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
                    memory,
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
fn link_tx_sender_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "tx_sender",
            |mut caller: Caller<'_, ClarityWasmContext>,
             return_offset: i32,
             _return_length: i32| {
                let sender = caller.data().sender.clone().ok_or(Error::Runtime(
                    RuntimeErrorType::NoSenderInContext.into(),
                    None,
                ))?;

                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let (_, bytes_written) = write_to_wasm(
                    &mut caller,
                    memory,
                    &TypeSignature::PrincipalType,
                    return_offset,
                    return_offset,
                    &Value::Principal(sender),
                    false,
                )?;

                Ok((return_offset, bytes_written))
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
fn link_contract_caller_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "contract_caller",
            |mut caller: Caller<'_, ClarityWasmContext>,
             return_offset: i32,
             _return_length: i32| {
                let contract_caller = caller.data().caller.clone().ok_or(Error::Runtime(
                    RuntimeErrorType::NoCallerInContext.into(),
                    None,
                ))?;

                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let (_, bytes_written) = write_to_wasm(
                    &mut caller,
                    memory,
                    &TypeSignature::PrincipalType,
                    return_offset,
                    return_offset,
                    &Value::Principal(contract_caller),
                    false,
                )?;

                Ok((return_offset, bytes_written))
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
fn link_tx_sponsor_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "tx_sponsor",
            |mut caller: Caller<'_, ClarityWasmContext>,
             return_offset: i32,
             _return_length: i32| {
                let opt_sponsor = caller.data().sponsor.clone();
                if let Some(sponsor) = opt_sponsor {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|export| export.into_memory())
                        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                    let (_, bytes_written) = write_to_wasm(
                        &mut caller,
                        memory,
                        &TypeSignature::PrincipalType,
                        return_offset,
                        return_offset,
                        &Value::Principal(sponsor),
                        false,
                    )?;

                    Ok((1i32, return_offset, bytes_written))
                } else {
                    Ok((0i32, return_offset, 0i32))
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
fn link_block_height_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "block_height",
            |mut caller: Caller<'_, ClarityWasmContext>| {
                let height = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_current_block_height();
                Ok((height as i64, 0i64))
            },
        )
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
fn link_burn_block_height_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "burn_block_height",
            |mut caller: Caller<'_, ClarityWasmContext>| {
                let height = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_current_burnchain_block_height();
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
fn link_stx_liquid_supply_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "stx_liquid_supply",
            |mut caller: Caller<'_, ClarityWasmContext>| {
                let supply = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_total_liquid_ustx();
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
fn link_is_in_regtest_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "is_in_regtest",
            |caller: Caller<'_, ClarityWasmContext>| {
                if caller.data().global_context.database.is_in_regtest() {
                    Ok(1i32)
                } else {
                    Ok(0i32)
                }
            },
        )
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
fn link_is_in_mainnet_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "is_in_mainnet",
            |caller: Caller<'_, ClarityWasmContext>| {
                if caller.data().global_context.mainnet {
                    Ok(1i32)
                } else {
                    Ok(0i32)
                }
            },
        )
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
fn link_chain_id_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "chain_id",
            |caller: Caller<'_, ClarityWasmContext>| {
                let chain_id = caller.data().global_context.chain_id;
                Ok((chain_id as i64, 0i64))
            },
        )
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
fn link_enter_as_contract_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "enter_as_contract",
            |mut caller: Caller<'_, ClarityWasmContext>| {
                let contract_principal: PrincipalData = caller
                    .data()
                    .contract_context()
                    .contract_identifier
                    .clone()
                    .into();
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
fn link_exit_as_contract_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "exit_as_contract",
            |mut caller: Caller<'_, ClarityWasmContext>| {
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
fn link_stx_get_balance_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "stx_get_balance",
            |mut caller: Caller<'_, ClarityWasmContext>,
             principal_offset: i32,
             principal_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Read the principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    principal_offset,
                    principal_length,
                )?;
                let principal = value_as_principal(&value)?;

                let balance = {
                    let mut snapshot = caller
                        .data_mut()
                        .global_context
                        .database
                        .get_stx_balance_snapshot(principal);
                    snapshot.get_available_balance()
                };
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
fn link_stx_account_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "stx_account",
            |mut caller: Caller<'_, ClarityWasmContext>,
             principal_offset: i32,
             principal_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Read the principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    principal_offset,
                    principal_length,
                )?;
                let principal = value_as_principal(&value)?;

                let account = {
                    let mut snapshot = caller
                        .data_mut()
                        .global_context
                        .database
                        .get_stx_balance_snapshot(principal);
                    snapshot.canonical_balance_repr()
                };
                let v1_unlock_ht = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_v1_unlock_height();
                let v2_unlock_ht = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_v2_unlock_height();

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

fn link_stx_burn_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "stx_burn",
            |mut caller: Caller<'_, ClarityWasmContext>,
             amount_lo: i64,
             amount_hi: i64,
             principal_offset: i32,
             principal_length: i32| {
                let amount = (amount_hi as u128) << 64 | (amount_lo as u128);

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Read the principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    principal_offset,
                    principal_length,
                )?;
                let from = value_as_principal(&value)?;

                if amount == 0 {
                    return Ok((0i32, 0i32, StxErrorCodes::NON_POSITIVE_AMOUNT as i64, 0i64));
                }

                if Some(from) != caller.data().sender.as_ref() {
                    return Ok((
                        0i32,
                        0i32,
                        StxErrorCodes::SENDER_IS_NOT_TX_SENDER as i64,
                        0i64,
                    ));
                }

                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(STXBalance::unlocked_and_v1_size as u64)
                    .map_err(|e| Error::from(e))?;

                let mut burner_snapshot = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_stx_balance_snapshot(&from);
                if !burner_snapshot.can_transfer(amount) {
                    return Ok((0i32, 0i32, StxErrorCodes::NOT_ENOUGH_BALANCE as i64, 0i64));
                }

                burner_snapshot.debit(amount);
                burner_snapshot.save();

                caller
                    .data_mut()
                    .global_context
                    .database
                    .decrement_ustx_liquid_supply(amount)?;

                caller
                    .data_mut()
                    .global_context
                    .log_stx_burn(&from, amount)?;
                caller
                    .data_mut()
                    .register_stx_burn_event(from.clone(), amount)?;

                // (ok true)
                Ok((1i32, 1i32, 0i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "stx_burn".to_string(),
                e,
            ))
        })
}

fn link_stx_transfer_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "stx_transfer",
            |mut caller: Caller<'_, ClarityWasmContext>,
             amount_lo: i64,
             amount_hi: i64,
             sender_offset: i32,
             sender_length: i32,
             recipient_offset: i32,
             recipient_length: i32,
             memo_offset: i32,
             memo_length: i32| {
                let amount = (amount_hi as u128) << 64 | (amount_lo as u128);

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Read the sender principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    sender_offset,
                    sender_length,
                )?;
                let sender = value_as_principal(&value)?;

                // Read the to principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    recipient_offset,
                    recipient_length,
                )?;
                let recipient = value_as_principal(&value)?;

                // Read the memo from the Wasm memory
                let memo = if memo_length > 0 {
                    let value = read_from_wasm(
                        memory,
                        &mut caller,
                        &TypeSignature::SequenceType(SequenceSubtype::BufferType(
                            BufferLength::try_from(memo_length as u32)?,
                        )),
                        memo_offset,
                        memo_length,
                    )?;
                    value_as_buffer(value)?
                } else {
                    BuffData::empty()
                };

                if amount == 0 {
                    return Ok((0i32, 0i32, StxErrorCodes::NON_POSITIVE_AMOUNT as i64, 0i64));
                }

                if sender == recipient {
                    return Ok((0i32, 0i32, StxErrorCodes::SENDER_IS_RECIPIENT as i64, 0i64));
                }

                if Some(sender) != caller.data().sender.as_ref() {
                    return Ok((
                        0i32,
                        0i32,
                        StxErrorCodes::SENDER_IS_NOT_TX_SENDER as i64,
                        0i64,
                    ));
                }

                // loading sender/recipient principals and balances
                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                // loading sender's locked amount and height
                // TODO: this does not count the inner stacks block header load, but arguably,
                // this could be optimized away, so it shouldn't penalize the caller.
                caller
                    .data_mut()
                    .global_context
                    .add_memory(STXBalance::unlocked_and_v1_size as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(STXBalance::unlocked_and_v1_size as u64)
                    .map_err(|e| Error::from(e))?;

                let mut sender_snapshot = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_stx_balance_snapshot(sender);
                if !sender_snapshot.can_transfer(amount) {
                    return Ok((0i32, 0i32, StxErrorCodes::NOT_ENOUGH_BALANCE as i64, 0i64));
                }

                sender_snapshot.transfer_to(recipient, amount)?;

                caller
                    .data_mut()
                    .global_context
                    .log_stx_transfer(&sender, amount)?;
                caller.data_mut().register_stx_transfer_event(
                    sender.clone(),
                    recipient.clone(),
                    amount,
                    memo,
                )?;

                // (ok true)
                Ok((1i32, 1i32, 0i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "stx_transfer".to_string(),
                e,
            ))
        })
}

fn link_ft_get_supply_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "ft_get_supply",
            |mut caller: Caller<'_, ClarityWasmContext>, name_offset: i32, name_length: i32| {
                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // runtime_cost(ClarityCostFunction::FtSupply, env, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the token name
                let token_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let supply = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_ft_supply(&contract_identifier, &token_name)?;

                let high = (supply >> 64) as u64;
                let low = (supply & 0xffff_ffff_ffff_ffff) as u64;
                Ok((low, high))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "ft_get_supply".to_string(),
                e,
            ))
        })
}

fn link_ft_get_balance_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "ft_get_balance",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             owner_offset: i32,
             owner_length: i32| {
                // runtime_cost(ClarityCostFunction::FtBalance, env, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the token name
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let token_name = ClarityName::try_from(name.clone())?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // Read the owner principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    owner_offset,
                    owner_length,
                )?;
                let owner = value_as_principal(&value)?;

                let ft_info = caller
                    .data()
                    .contract_context()
                    .meta_ft
                    .get(&token_name)
                    .ok_or(CheckErrors::NoSuchFT(token_name.to_string()))?
                    .clone();

                let balance = caller.data_mut().global_context.database.get_ft_balance(
                    &contract_identifier,
                    token_name.as_str(),
                    owner,
                    Some(&ft_info),
                )?;

                let high = (balance >> 64) as u64;
                let low = (balance & 0xffff_ffff_ffff_ffff) as u64;
                Ok((low, high))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "ft_get_balance".to_string(),
                e,
            ))
        })
}

fn link_ft_burn_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "ft_burn",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             amount_lo: i64,
             amount_hi: i64,
             sender_offset: i32,
             sender_length: i32| {
                // runtime_cost(ClarityCostFunction::FtBurn, env, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // Retrieve the token name
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let token_name = ClarityName::try_from(name.clone())?;

                // Compute the amount
                let amount = (amount_hi as u128) << 64 | (amount_lo as u128);

                // Read the sender principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    sender_offset,
                    sender_length,
                )?;
                let burner = value_as_principal(&value)?;

                if amount == 0 {
                    return Ok((
                        0i32,
                        0i32,
                        BurnTokenErrorCodes::NOT_ENOUGH_BALANCE_OR_NON_POSITIVE as i64,
                        0i64,
                    ));
                }

                let burner_bal = caller.data_mut().global_context.database.get_ft_balance(
                    &contract_identifier,
                    token_name.as_str(),
                    burner,
                    None,
                )?;

                if amount > burner_bal {
                    return Ok((
                        0i32,
                        0i32,
                        BurnTokenErrorCodes::NOT_ENOUGH_BALANCE_OR_NON_POSITIVE as i64,
                        0i64,
                    ));
                }

                caller
                    .data_mut()
                    .global_context
                    .database
                    .checked_decrease_token_supply(
                        &contract_identifier,
                        token_name.as_str(),
                        amount,
                    )?;

                let final_burner_bal = burner_bal - amount;

                caller.data_mut().global_context.database.set_ft_balance(
                    &contract_identifier,
                    token_name.as_str(),
                    burner,
                    final_burner_bal,
                )?;

                let asset_identifier = AssetIdentifier {
                    contract_identifier: contract_identifier.clone(),
                    asset_name: token_name.clone(),
                };
                caller.data_mut().register_ft_burn_event(
                    burner.clone(),
                    amount,
                    asset_identifier,
                )?;

                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::UIntType.size() as u64)
                    .map_err(|e| Error::from(e))?;

                caller.data_mut().global_context.log_token_transfer(
                    burner,
                    &contract_identifier,
                    &token_name,
                    amount,
                )?;

                // (ok true)
                Ok((1i32, 1i32, 0i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "ft_burn".to_string(),
                e,
            ))
        })
}

fn link_ft_mint_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "ft_mint",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             amount_lo: i64,
             amount_hi: i64,
             sender_offset: i32,
             sender_length: i32| {
                // runtime_cost(ClarityCostFunction::FtBurn, env, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // Retrieve the token name
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let token_name = ClarityName::try_from(name.clone())?;

                // Compute the amount
                let amount = (amount_hi as u128) << 64 | (amount_lo as u128);

                // Read the sender principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    sender_offset,
                    sender_length,
                )?;
                let to_principal = value_as_principal(&value)?;

                if amount == 0 {
                    return Ok((
                        0i32,
                        0i32,
                        MintTokenErrorCodes::NON_POSITIVE_AMOUNT as i64,
                        0i64,
                    ));
                }

                let ft_info = caller
                    .data()
                    .contract_context()
                    .meta_ft
                    .get(token_name.as_str())
                    .ok_or(CheckErrors::NoSuchFT(token_name.to_string()))?
                    .clone();

                caller
                    .data_mut()
                    .global_context
                    .database
                    .checked_increase_token_supply(
                        &contract_identifier,
                        token_name.as_str(),
                        amount,
                        &ft_info,
                    )?;

                let to_bal = caller.data_mut().global_context.database.get_ft_balance(
                    &contract_identifier,
                    token_name.as_str(),
                    to_principal,
                    Some(&ft_info),
                )?;

                // This `expect` is safe because the `checked_increase_token_supply` call above
                // would have failed if the addition would have overflowed.
                let final_to_bal = to_bal.checked_add(amount).expect("FT overflow");

                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::UIntType.size() as u64)
                    .map_err(|e| Error::from(e))?;

                caller.data_mut().global_context.database.set_ft_balance(
                    &contract_identifier,
                    token_name.as_str(),
                    to_principal,
                    final_to_bal,
                )?;

                let asset_identifier = AssetIdentifier {
                    contract_identifier: contract_identifier.clone(),
                    asset_name: token_name.clone(),
                };
                caller.data_mut().register_ft_mint_event(
                    to_principal.clone(),
                    amount,
                    asset_identifier,
                )?;

                // (ok true)
                Ok((1i32, 1i32, 0i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "ft_mint".to_string(),
                e,
            ))
        })
}

fn link_ft_transfer_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "ft_transfer",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             amount_lo: i64,
             amount_hi: i64,
             sender_offset: i32,
             sender_length: i32,
             recipient_offset: i32,
             recipient_length: i32| {
                // runtime_cost(ClarityCostFunction::FtTransfer, env, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // Retrieve the token name
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let token_name = ClarityName::try_from(name.clone())?;

                // Compute the amount
                let amount = (amount_hi as u128) << 64 | (amount_lo as u128);

                // Read the sender principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    sender_offset,
                    sender_length,
                )?;
                let from_principal = value_as_principal(&value)?;

                // Read the recipient principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    recipient_offset,
                    recipient_length,
                )?;
                let to_principal = value_as_principal(&value)?;

                if amount == 0 {
                    return Ok((
                        0i32,
                        0i32,
                        TransferTokenErrorCodes::NON_POSITIVE_AMOUNT as i64,
                        0i64,
                    ));
                }

                if from_principal == to_principal {
                    return Ok((
                        0i32,
                        0i32,
                        TransferTokenErrorCodes::SENDER_IS_RECIPIENT as i64,
                        0i64,
                    ));
                }

                let ft_info = caller
                    .data()
                    .contract_context()
                    .meta_ft
                    .get(&token_name)
                    .ok_or(CheckErrors::NoSuchFT(token_name.to_string()))?
                    .clone();

                let from_bal = caller.data_mut().global_context.database.get_ft_balance(
                    &contract_identifier,
                    token_name.as_str(),
                    from_principal,
                    Some(&ft_info),
                )?;

                if from_bal < amount {
                    return Ok((
                        0i32,
                        0i32,
                        TransferTokenErrorCodes::NOT_ENOUGH_BALANCE as i64,
                        0i64,
                    ));
                }

                let final_from_bal = from_bal - amount;

                let to_bal = caller.data_mut().global_context.database.get_ft_balance(
                    &contract_identifier,
                    token_name.as_str(),
                    to_principal,
                    Some(&ft_info),
                )?;

                let final_to_bal = to_bal
                    .checked_add(amount)
                    .ok_or(RuntimeErrorType::ArithmeticOverflow)?;

                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::UIntType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::UIntType.size() as u64)
                    .map_err(|e| Error::from(e))?;

                caller.data_mut().global_context.database.set_ft_balance(
                    &contract_identifier,
                    &token_name,
                    from_principal,
                    final_from_bal,
                )?;
                caller.data_mut().global_context.database.set_ft_balance(
                    &contract_identifier,
                    token_name.as_str(),
                    to_principal,
                    final_to_bal,
                )?;

                caller.data_mut().global_context.log_token_transfer(
                    from_principal,
                    &contract_identifier,
                    &token_name,
                    amount,
                )?;

                let asset_identifier = AssetIdentifier {
                    contract_identifier: contract_identifier.clone(),
                    asset_name: token_name.clone(),
                };
                caller.data_mut().register_ft_transfer_event(
                    from_principal.clone(),
                    to_principal.clone(),
                    amount,
                    asset_identifier,
                )?;

                // (ok true)
                Ok((1i32, 1i32, 0i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "ft_transfer".to_string(),
                e,
            ))
        })
}

fn link_nft_get_owner_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "nft_get_owner",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             asset_offset: i32,
             asset_length: i32,
             return_offset: i32,
             _return_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // Retrieve the token name
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let asset_name = ClarityName::try_from(name.clone())?;

                let nft_metadata = caller
                    .data()
                    .contract_context()
                    .meta_nft
                    .get(&asset_name)
                    .ok_or(CheckErrors::NoSuchNFT(asset_name.to_string()))?
                    .clone();

                let expected_asset_type = &nft_metadata.key_type;

                // Read in the NFT identifier from the Wasm memory
                let asset = read_from_wasm(
                    memory,
                    &mut caller,
                    expected_asset_type,
                    asset_offset,
                    asset_length,
                )?;

                let _asset_size = asset.serialized_size() as u64;

                // runtime_cost(ClarityCostFunction::NftOwner, env, asset_size)?;

                if !expected_asset_type.admits(&caller.data().global_context.epoch_id, &asset)? {
                    return Err(
                        CheckErrors::TypeValueError(expected_asset_type.clone(), asset).into(),
                    );
                }

                match caller.data_mut().global_context.database.get_nft_owner(
                    &contract_identifier,
                    asset_name.as_str(),
                    &asset,
                    expected_asset_type,
                ) {
                    Ok(owner) => {
                        // Write the principal to the return buffer
                        let memory = caller
                            .get_export("memory")
                            .and_then(|export| export.into_memory())
                            .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                        let (_, bytes_written) = write_to_wasm(
                            caller,
                            memory,
                            &TypeSignature::PrincipalType,
                            return_offset,
                            return_offset,
                            &Value::Principal(owner),
                            false,
                        )?;

                        Ok((1i32, return_offset, bytes_written))
                    }
                    Err(Error::Runtime(RuntimeErrorType::NoSuchToken, _)) => Ok((0i32, 0i32, 0i32)),
                    Err(e) => {
                        return Err(e)?;
                    }
                }
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "nft_get_owner".to_string(),
                e,
            ))
        })
}

fn link_nft_burn_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "nft_burn",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             asset_offset: i32,
             asset_length: i32,
             sender_offset: i32,
             sender_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // Retrieve the token name
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let asset_name = ClarityName::try_from(name.clone())?;

                let nft_metadata = caller
                    .data()
                    .contract_context()
                    .meta_nft
                    .get(&asset_name)
                    .ok_or(CheckErrors::NoSuchNFT(asset_name.to_string()))?
                    .clone();

                let expected_asset_type = &nft_metadata.key_type;

                // Read in the NFT identifier from the Wasm memory
                let asset = read_from_wasm(
                    memory,
                    &mut caller,
                    expected_asset_type,
                    asset_offset,
                    asset_length,
                )?;

                // Read the sender principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    sender_offset,
                    sender_length,
                )?;
                let sender_principal = value_as_principal(&value)?;

                let asset_size = asset.serialized_size() as u64;

                // runtime_cost(ClarityCostFunction::NftBurn, env, asset_size)?;

                if !expected_asset_type.admits(&caller.data().global_context.epoch_id, &asset)? {
                    return Err(
                        CheckErrors::TypeValueError(expected_asset_type.clone(), asset).into(),
                    );
                }

                let owner = match caller.data_mut().global_context.database.get_nft_owner(
                    &contract_identifier,
                    asset_name.as_str(),
                    &asset,
                    expected_asset_type,
                ) {
                    Err(Error::Runtime(RuntimeErrorType::NoSuchToken, _)) => {
                        return Ok((0i32, 0i32, BurnAssetErrorCodes::DOES_NOT_EXIST as i64, 0i64));
                    }
                    Ok(owner) => Ok(owner),
                    Err(e) => Err(e),
                }?;

                if &owner != sender_principal {
                    return Ok((0i32, 0i32, BurnAssetErrorCodes::NOT_OWNED_BY as i64, 0i64));
                }

                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(asset_size)
                    .map_err(|e| Error::from(e))?;

                caller.data_mut().global_context.database.burn_nft(
                    &contract_identifier,
                    asset_name.as_str(),
                    &asset,
                    expected_asset_type,
                )?;

                caller.data_mut().global_context.log_asset_transfer(
                    sender_principal,
                    &contract_identifier,
                    &asset_name,
                    asset.clone(),
                );

                let asset_identifier = AssetIdentifier {
                    contract_identifier,
                    asset_name: asset_name.clone(),
                };
                caller.data_mut().register_nft_burn_event(
                    sender_principal.clone(),
                    asset,
                    asset_identifier,
                )?;

                // (ok true)
                Ok((1i32, 132, 0i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "nft_burn".to_string(),
                e,
            ))
        })
}

fn link_nft_mint_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "nft_mint",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             asset_offset: i32,
             asset_length: i32,
             recipient_offset: i32,
             recipient_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // Retrieve the token name
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let asset_name = ClarityName::try_from(name.clone())?;

                let nft_metadata = caller
                    .data()
                    .contract_context()
                    .meta_nft
                    .get(&asset_name)
                    .ok_or(CheckErrors::NoSuchNFT(asset_name.to_string()))?
                    .clone();

                let expected_asset_type = &nft_metadata.key_type;

                // Read in the NFT identifier from the Wasm memory
                let asset = read_from_wasm(
                    memory,
                    &mut caller,
                    expected_asset_type,
                    asset_offset,
                    asset_length,
                )?;

                // Read the recipient principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    recipient_offset,
                    recipient_length,
                )?;
                let to_principal = value_as_principal(&value)?;

                let asset_size = asset.serialized_size() as u64;
                // runtime_cost(ClarityCostFunction::NftMint, env, asset_size)?;

                if !expected_asset_type.admits(&caller.data().global_context.epoch_id, &asset)? {
                    return Err(
                        CheckErrors::TypeValueError(expected_asset_type.clone(), asset).into(),
                    );
                }

                match caller.data_mut().global_context.database.get_nft_owner(
                    &contract_identifier,
                    asset_name.as_str(),
                    &asset,
                    expected_asset_type,
                ) {
                    Err(Error::Runtime(RuntimeErrorType::NoSuchToken, _)) => Ok(()),
                    Ok(_owner) => {
                        return Ok((0i32, 0i32, MintAssetErrorCodes::ALREADY_EXIST as i64, 0i64))
                    }
                    Err(e) => Err(e),
                }?;

                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(asset_size)
                    .map_err(|e| Error::from(e))?;

                caller.data_mut().global_context.database.set_nft_owner(
                    &contract_identifier,
                    asset_name.as_str(),
                    &asset,
                    to_principal,
                    expected_asset_type,
                )?;

                let asset_identifier = AssetIdentifier {
                    contract_identifier,
                    asset_name: asset_name.clone(),
                };
                caller.data_mut().register_nft_mint_event(
                    to_principal.clone(),
                    asset,
                    asset_identifier,
                )?;

                // (ok true)
                Ok((1i32, 132, 0i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "nft_mint".to_string(),
                e,
            ))
        })
}

fn link_nft_transfer_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "nft_transfer",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             asset_offset: i32,
             asset_length: i32,
             sender_offset: i32,
             sender_length: i32,
             recipient_offset: i32,
             recipient_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

                // Retrieve the token name
                let name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;
                let asset_name = ClarityName::try_from(name.clone())?;

                let nft_metadata = caller
                    .data()
                    .contract_context()
                    .meta_nft
                    .get(&asset_name)
                    .ok_or(CheckErrors::NoSuchNFT(asset_name.to_string()))?
                    .clone();

                let expected_asset_type = &nft_metadata.key_type;

                // Read in the NFT identifier from the Wasm memory
                let asset = read_from_wasm(
                    memory,
                    &mut caller,
                    expected_asset_type,
                    asset_offset,
                    asset_length,
                )?;

                // Read the sender principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    sender_offset,
                    sender_length,
                )?;
                let from_principal = value_as_principal(&value)?;

                // Read the recipient principal from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    recipient_offset,
                    recipient_length,
                )?;
                let to_principal = value_as_principal(&value)?;

                let asset_size = asset.serialized_size() as u64;
                // runtime_cost(ClarityCostFunction::NftTransfer, env, asset_size)?;

                if !expected_asset_type.admits(&caller.data().global_context.epoch_id, &asset)? {
                    return Err(
                        CheckErrors::TypeValueError(expected_asset_type.clone(), asset).into(),
                    );
                }

                if from_principal == to_principal {
                    return Ok((
                        0i32,
                        0i32,
                        TransferAssetErrorCodes::SENDER_IS_RECIPIENT as i64,
                        0i64,
                    ));
                }

                let current_owner = match caller.data_mut().global_context.database.get_nft_owner(
                    &contract_identifier,
                    asset_name.as_str(),
                    &asset,
                    expected_asset_type,
                ) {
                    Ok(owner) => Ok(owner),
                    Err(Error::Runtime(RuntimeErrorType::NoSuchToken, _)) => {
                        return Ok((
                            0i32,
                            0i32,
                            TransferAssetErrorCodes::DOES_NOT_EXIST as i64,
                            0i64,
                        ))
                    }
                    Err(e) => Err(e),
                }?;

                if current_owner != *from_principal {
                    return Ok((
                        0i32,
                        0i32,
                        TransferAssetErrorCodes::NOT_OWNED_BY as i64,
                        0i64,
                    ));
                }

                caller
                    .data_mut()
                    .global_context
                    .add_memory(TypeSignature::PrincipalType.size() as u64)
                    .map_err(|e| Error::from(e))?;
                caller
                    .data_mut()
                    .global_context
                    .add_memory(asset_size)
                    .map_err(|e| Error::from(e))?;

                caller.data_mut().global_context.database.set_nft_owner(
                    &contract_identifier,
                    asset_name.as_str(),
                    &asset,
                    to_principal,
                    expected_asset_type,
                )?;

                caller.data_mut().global_context.log_asset_transfer(
                    from_principal,
                    &contract_identifier,
                    &asset_name,
                    asset.clone(),
                );

                let asset_identifier = AssetIdentifier {
                    contract_identifier,
                    asset_name,
                };
                caller.data_mut().register_nft_transfer_event(
                    from_principal.clone(),
                    to_principal.clone(),
                    asset,
                    asset_identifier,
                )?;

                // (ok true)
                Ok((1i32, 132, 0i64, 0i64))
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "nft_transfer".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `map_get`, into the Wasm module.
/// This function is called for the `map-get?` expression.
fn link_map_get_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "map_get",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             key_offset: i32,
             key_length: i32,
             return_offset: i32,
             _return_length: i32| {
                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the map name
                let map_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let contract = caller.data().contract_context().contract_identifier.clone();

                // Retrieve the metadata for this map
                let data_types = caller
                    .data()
                    .contract_context()
                    .meta_data_map
                    .get(map_name.as_str())
                    .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?
                    .clone();

                // Read in the key from the Wasm memory
                let key = read_from_wasm(
                    memory,
                    &mut caller,
                    &data_types.key_type,
                    key_offset,
                    key_length,
                )?;

                let result = caller
                    .data_mut()
                    .global_context
                    .database
                    .fetch_entry_with_size(&contract, &map_name, &key, &data_types);

                let _result_size = match &result {
                    Ok(data) => data.serialized_byte_len,
                    Err(_e) => (data_types.value_type.size() + data_types.key_type.size()) as u64,
                };

                // runtime_cost(ClarityCostFunction::FetchEntry, env, result_size)?;

                let value = result.map(|data| data.value)?;

                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                let ty = TypeSignature::OptionalType(Box::new(data_types.value_type));
                write_to_wasm(
                    &mut caller,
                    memory,
                    &ty,
                    return_offset,
                    return_offset + get_type_size(&ty),
                    &value,
                    true,
                )?;

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "map_get".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `map_set`, into the Wasm module.
/// This function is called for the `map-set` expression.
fn link_map_set_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "map_set",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             key_offset: i32,
             key_length: i32,
             value_offset: i32,
             value_length: i32| {
                if caller.data().global_context.is_read_only() {
                    return Err(CheckErrors::WriteAttemptedInReadOnly.into());
                }

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the map name
                let map_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let contract = caller.data().contract_context().contract_identifier.clone();

                let data_types = caller
                    .data()
                    .contract_context()
                    .meta_data_map
                    .get(map_name.as_str())
                    .ok_or(Error::Unchecked(CheckErrors::NoSuchMap(
                        map_name.to_string(),
                    )))?
                    .clone();

                // Read in the key from the Wasm memory
                let key = read_from_wasm(
                    memory,
                    &mut caller,
                    &data_types.key_type,
                    key_offset,
                    key_length,
                )?;

                // Read in the value from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &data_types.value_type,
                    value_offset,
                    value_length,
                )?;

                // Store the value in the map in the global context
                let result = caller.data_mut().global_context.database.set_entry(
                    &contract,
                    map_name.as_str(),
                    key,
                    value,
                    &data_types,
                );

                let result_size = match &result {
                    Ok(data) => data.serialized_byte_len,
                    Err(_e) => (data_types.value_type.size() + data_types.key_type.size()) as u64,
                };

                // runtime_cost(ClarityCostFunction::SetEntry, env, result_size)?;

                caller
                    .data_mut()
                    .global_context
                    .add_memory(result_size)
                    .map_err(|e| Error::from(e))?;

                let value = result.map(|data| data.value)?;
                if let Value::Bool(true) = value {
                    Ok(1i32)
                } else {
                    Ok(0i32)
                }
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "map_set".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `map_insert`, into the Wasm module.
/// This function is called for the `map-insert` expression.
fn link_map_insert_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "map_insert",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             key_offset: i32,
             key_length: i32,
             value_offset: i32,
             value_length: i32| {
                if caller.data().global_context.is_read_only() {
                    return Err(CheckErrors::WriteAttemptedInReadOnly.into());
                }

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the map name
                let map_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let contract = caller.data().contract_context().contract_identifier.clone();

                let data_types = caller
                    .data()
                    .contract_context()
                    .meta_data_map
                    .get(map_name.as_str())
                    .ok_or(Error::Unchecked(CheckErrors::NoSuchMap(
                        map_name.to_string(),
                    )))?
                    .clone();

                // Read in the key from the Wasm memory
                let key = read_from_wasm(
                    memory,
                    &mut caller,
                    &data_types.key_type,
                    key_offset,
                    key_length,
                )?;

                // Read in the value from the Wasm memory
                let value = read_from_wasm(
                    memory,
                    &mut caller,
                    &data_types.value_type,
                    value_offset,
                    value_length,
                )?;

                // Insert the value into the map
                let result = caller.data_mut().global_context.database.insert_entry(
                    &contract,
                    map_name.as_str(),
                    key,
                    value,
                    &data_types,
                );

                let result_size = match &result {
                    Ok(data) => data.serialized_byte_len,
                    Err(_e) => (data_types.value_type.size() + data_types.key_type.size()) as u64,
                };

                // runtime_cost(ClarityCostFunction::SetEntry, env, result_size)?;

                caller
                    .data_mut()
                    .global_context
                    .add_memory(result_size)
                    .map_err(|e| Error::from(e))?;

                let value = result.map(|data| data.value)?;
                if let Value::Bool(true) = value {
                    Ok(1i32)
                } else {
                    Ok(0i32)
                }
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "map_insert".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `map_delete`, into the Wasm module.
/// This function is called for the `map-delete` expression.
fn link_map_delete_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "map_delete",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             key_offset: i32,
             key_length: i32| {
                if caller.data().global_context.is_read_only() {
                    return Err(CheckErrors::WriteAttemptedInReadOnly.into());
                }

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the map name
                let map_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let contract = caller.data().contract_context().contract_identifier.clone();

                let data_types = caller
                    .data()
                    .contract_context()
                    .meta_data_map
                    .get(map_name.as_str())
                    .ok_or(Error::Unchecked(CheckErrors::NoSuchMap(
                        map_name.to_string(),
                    )))?
                    .clone();

                // Read in the key from the Wasm memory
                let key = read_from_wasm(
                    memory,
                    &mut caller,
                    &data_types.key_type,
                    key_offset,
                    key_length,
                )?;

                // Delete the key from the map in the global context
                let result = caller.data_mut().global_context.database.delete_entry(
                    &contract,
                    map_name.as_str(),
                    &key,
                    &data_types,
                );

                let result_size = match &result {
                    Ok(data) => data.serialized_byte_len,
                    Err(_e) => (data_types.value_type.size() + data_types.key_type.size()) as u64,
                };

                // runtime_cost(ClarityCostFunction::SetEntry, env, result_size)?;

                caller
                    .data_mut()
                    .global_context
                    .add_memory(result_size)
                    .map_err(|e| Error::from(e))?;

                let value = result.map(|data| data.value)?;
                if let Value::Bool(true) = value {
                    Ok(1i32)
                } else {
                    Ok(0i32)
                }
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "map_delete".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `get_block_info`, into the Wasm module.
/// This function is called for the `get-block-info?` expression.
fn link_get_block_info_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "get_block_info",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             height_lo: i64,
             height_hi: i64,
             return_offset: i32,
             _return_length: i32| {
                // runtime_cost(ClarityCostFunction::BlockInfo, env, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the property name
                let property_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let height = (height_lo as u128) | ((height_hi as u128) << 64);

                let block_info_prop = BlockInfoProperty::lookup_by_name_at_version(
                    &property_name,
                    caller.data().contract_context().get_clarity_version(),
                )
                .ok_or(CheckErrors::GetBlockInfoExpectPropertyName)?;

                let height_value = match u32::try_from(height) {
                    Ok(result) => result,
                    _ => {
                        // Write a 0 to the return buffer for `none`
                        write_to_wasm(
                            &mut caller,
                            memory,
                            &TypeSignature::BoolType,
                            return_offset,
                            return_offset + get_type_size(&TypeSignature::BoolType),
                            &Value::Bool(false),
                            true,
                        )?;
                        return Ok(());
                    }
                };

                let current_block_height = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_current_block_height();
                if height_value >= current_block_height {
                    // Write a 0 to the return buffer for `none`
                    write_to_wasm(
                        &mut caller,
                        memory,
                        &TypeSignature::BoolType,
                        return_offset,
                        return_offset + get_type_size(&TypeSignature::BoolType),
                        &Value::Bool(false),
                        true,
                    )?;
                    return Ok(());
                }

                let (result, result_ty) = match block_info_prop {
                    BlockInfoProperty::Time => {
                        let block_time = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_block_time(height_value);
                        (Value::UInt(block_time as u128), TypeSignature::UIntType)
                    }
                    BlockInfoProperty::VrfSeed => {
                        let vrf_seed = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_block_vrf_seed(height_value);
                        let data = vrf_seed.as_bytes().to_vec();
                        let len = data.len() as u32;
                        (
                            Value::Sequence(SequenceData::Buffer(BuffData { data })),
                            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                                BufferLength::try_from(len)?,
                            )),
                        )
                    }
                    BlockInfoProperty::HeaderHash => {
                        let header_hash = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_block_header_hash(height_value);
                        let data = header_hash.as_bytes().to_vec();
                        let len = data.len() as u32;
                        (
                            Value::Sequence(SequenceData::Buffer(BuffData { data })),
                            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                                BufferLength::try_from(len)?,
                            )),
                        )
                    }
                    BlockInfoProperty::BurnchainHeaderHash => {
                        let burnchain_header_hash = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_burnchain_block_header_hash(height_value);
                        let data = burnchain_header_hash.as_bytes().to_vec();
                        let len = data.len() as u32;
                        (
                            Value::Sequence(SequenceData::Buffer(BuffData { data })),
                            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                                BufferLength::try_from(len)?,
                            )),
                        )
                    }
                    BlockInfoProperty::IdentityHeaderHash => {
                        let id_header_hash = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_index_block_header_hash(height_value);
                        let data = id_header_hash.as_bytes().to_vec();
                        let len = data.len() as u32;
                        (
                            Value::Sequence(SequenceData::Buffer(BuffData { data })),
                            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                                BufferLength::try_from(len)?,
                            )),
                        )
                    }
                    BlockInfoProperty::MinerAddress => {
                        let miner_address = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_miner_address(height_value);
                        (Value::from(miner_address), TypeSignature::PrincipalType)
                    }
                    BlockInfoProperty::MinerSpendWinner => {
                        let winner_spend = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_miner_spend_winner(height_value);
                        (Value::UInt(winner_spend), TypeSignature::UIntType)
                    }
                    BlockInfoProperty::MinerSpendTotal => {
                        let total_spend = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_miner_spend_total(height_value);
                        (Value::UInt(total_spend), TypeSignature::UIntType)
                    }
                    BlockInfoProperty::BlockReward => {
                        // this is already an optional
                        let block_reward_opt = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_block_reward(height_value);
                        (
                            match block_reward_opt {
                                Some(x) => Value::UInt(x),
                                None => {
                                    // Write a 0 to the return buffer for `none`
                                    write_to_wasm(
                                        &mut caller,
                                        memory,
                                        &TypeSignature::BoolType,
                                        return_offset,
                                        return_offset + get_type_size(&TypeSignature::BoolType),
                                        &Value::Bool(false),
                                        true,
                                    )?;
                                    return Ok(());
                                }
                            },
                            TypeSignature::UIntType,
                        )
                    }
                };

                // Write the result to the return buffer
                let ty = TypeSignature::OptionalType(Box::new(result_ty));
                write_to_wasm(
                    &mut caller,
                    memory,
                    &ty,
                    return_offset,
                    return_offset + get_type_size(&ty),
                    &Value::some(result)?,
                    true,
                )?;

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "get_block_info".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `get_burn_block_info`, into the Wasm module.
/// This function is called for the `get-burn-block-info?` expression.
fn link_get_burn_block_info_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "get_burn_block_info",
            |mut caller: Caller<'_, ClarityWasmContext>,
             name_offset: i32,
             name_length: i32,
             height_lo: i64,
             height_hi: i64,
             return_offset: i32,
             _return_length: i32| {
                // runtime_cost(ClarityCostFunction::GetBurnBlockInfo, env, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Retrieve the property name
                let property_name =
                    read_identifier_from_wasm(memory, &mut caller, name_offset, name_length)?;

                let height = (height_lo as u128) | ((height_hi as u128) << 64);

                let block_info_prop = BurnBlockInfoProperty::lookup_by_name(&property_name)
                    .ok_or(CheckErrors::GetBurnBlockInfoExpectPropertyName)?;

                // Note: we assume that we will not have a height bigger than u32::MAX.
                let height_value = match u32::try_from(height) {
                    Ok(result) => result,
                    _ => {
                        // Write a 0 to the return buffer for `none`
                        write_to_wasm(
                            &mut caller,
                            memory,
                            &TypeSignature::BoolType,
                            return_offset,
                            return_offset + get_type_size(&TypeSignature::BoolType),
                            &Value::Bool(false),
                            true,
                        )?;
                        return Ok(());
                    }
                };

                let (result, result_ty) = match block_info_prop {
                    BurnBlockInfoProperty::HeaderHash => {
                        let burnchain_header_hash_opt = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_burnchain_block_header_hash_for_burnchain_height(height_value);
                        (
                            match burnchain_header_hash_opt {
                                Some(burnchain_header_hash) => {
                                    Value::some(Value::Sequence(SequenceData::Buffer(BuffData {
                                        data: burnchain_header_hash.as_bytes().to_vec(),
                                    })))
                                    .expect("FATAL: could not wrap a (buff 32) in an optional")
                                }
                                None => Value::none(),
                            },
                            TypeSignature::OptionalType(Box::new(BUFF_32.clone())),
                        )
                    }
                    BurnBlockInfoProperty::PoxAddrs => {
                        let pox_addrs_and_payout = caller
                            .data_mut()
                            .global_context
                            .database
                            .get_pox_payout_addrs_for_burnchain_height(height_value);
                        let value = match pox_addrs_and_payout {
                            Some((addrs, payout)) => Value::some(Value::Tuple(
                                TupleData::from_data(vec![
                                    (
                                        "addrs".into(),
                                        Value::list_from(
                                            addrs.into_iter().map(Value::Tuple).collect(),
                                        )
                                        .expect("FATAL: could not convert address list to Value"),
                                    ),
                                    ("payout".into(), Value::UInt(payout)),
                                ])
                                .expect("FATAL: failed to build pox addrs and payout tuple"),
                            ))
                            .expect("FATAL: could not build Some(..)"),
                            None => Value::none(),
                        };
                        let addr_ty = TupleTypeSignature::try_from(vec![
                            ("hashbytes".into(), BUFF_32.clone()),
                            ("version".into(), BUFF_1.clone()),
                        ])
                        .expect("FATAL: could not build tuple type signature")
                        .into();
                        let addrs_ty = TypeSignature::list_of(addr_ty, 2)
                            .expect("FATAL: could not build list type signature");
                        let tuple_ty = TupleTypeSignature::try_from(vec![
                            ("addrs".into(), addrs_ty),
                            ("payout".into(), TypeSignature::UIntType),
                        ])?;
                        let ty = TypeSignature::OptionalType(Box::new(tuple_ty.into()));
                        (value, ty)
                    }
                };

                // Write the result to the return buffer
                let ty = TypeSignature::OptionalType(Box::new(result_ty));
                write_to_wasm(
                    &mut caller,
                    memory,
                    &ty,
                    return_offset,
                    return_offset + get_type_size(&ty),
                    &Value::some(result)?,
                    true,
                )?;

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "get_burn_block_info".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `contract_call`, into the Wasm module.
/// This function is called for `contract-call?`s with literal targets (not traits).
fn link_contract_call_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "contract_call",
            |mut caller: Caller<'_, ClarityWasmContext>,
             contract_offset: i32,
             contract_length: i32,
             function_offset: i32,
             function_length: i32,
             args_offset: i32,
             _args_length: i32,
             return_offset: i32,
             _return_length: i32| {
                // the second part of the contract_call cost (i.e., the load contract cost)
                //   is checked in `execute_contract`, and the function _application_ cost
                //   is checked in callables::DefinedFunction::execute_apply.
                // runtime_cost(ClarityCostFunction::ContractCall, env, 0)?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Read the contract identifier from the Wasm memory
                let contract_val = read_from_wasm(
                    memory,
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    contract_offset,
                    contract_length,
                )?;
                let contract_id = match &contract_val {
                    Value::Principal(PrincipalData::Contract(contract_id)) => contract_id,
                    _ => {
                        return Err(CheckErrors::ContractCallExpectName.into());
                    }
                };

                // Read the function name from the Wasm memory
                let function_name = read_identifier_from_wasm(
                    memory,
                    &mut caller,
                    function_offset,
                    function_length,
                )?;

                // Retrieve the contract context for the contract we're calling
                let contract = caller
                    .data_mut()
                    .global_context
                    .database
                    .get_contract(contract_id)?;

                // Retrieve the function we're calling
                let function = contract
                    .contract_context
                    .functions
                    .get(function_name.as_str())
                    .ok_or(CheckErrors::NoSuchPublicFunction(
                        contract_id.to_string(),
                        function_name.to_string(),
                    ))?;

                let mut args = Vec::new();
                let mut arg_offset = args_offset;
                // Read the arguments from the Wasm memory
                for arg_ty in function.get_arg_types() {
                    let arg = read_from_wasm_indirect(memory, &mut caller, arg_ty, arg_offset)?;
                    args.push(arg);

                    arg_offset += get_type_size(arg_ty);
                }

                let caller_contract: PrincipalData = caller
                    .data()
                    .contract_context()
                    .contract_identifier
                    .clone()
                    .into();
                caller.data_mut().push_caller(caller_contract.clone());

                let mut call_stack = caller.data().call_stack.clone();
                let sender = caller.data().sender.clone();
                let sponsor = caller.data().sponsor.clone();

                // FIXME: handle errors correctly!
                // TODO: define a new method on the context that handles some details of this
                let result = call_function(
                    &function_name,
                    &args,
                    caller.data_mut().global_context,
                    &contract.contract_context,
                    &mut call_stack,
                    sender,
                    Some(caller_contract),
                    sponsor,
                )?;

                // Write the result (if there is one) to the return buffer
                if let Some(return_ty) = function.get_return_type() {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|export| export.into_memory())
                        .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                    write_to_wasm(
                        &mut caller,
                        memory,
                        return_ty,
                        return_offset,
                        return_offset + get_type_size(return_ty),
                        &result,
                        true,
                    )?;
                }

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| {
            Error::Wasm(WasmError::UnableToLinkHostFunction(
                "contract_call".to_string(),
                e,
            ))
        })
}

/// Link host interface function, `print`, into the Wasm module.
/// This function is called for all contract print statements (`print`).
fn link_print_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "print",
            |mut caller: Caller<'_, ClarityWasmContext>, value_offset: i32, value_length: i32| {
                // runtime_cost(ClarityCostFunction::Print, env, input.size())?;

                // Get the memory from the caller
                let memory = caller
                    .get_export("memory")
                    .and_then(|export| export.into_memory())
                    .ok_or(Error::Wasm(WasmError::MemoryNotFound))?;

                // Read in the bytes from the Wasm memory
                let bytes = read_bytes_from_wasm(memory, &mut caller, value_offset, value_length)?;

                let clarity_val = Value::try_deserialize_bytes_untyped(&bytes)?;

                if cfg!(feature = "developer-mode") {
                    debug!("{}", &clarity_val);
                }

                caller.data_mut().register_print_event(clarity_val)?;

                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|e| Error::Wasm(WasmError::UnableToLinkHostFunction("print".to_string(), e)))
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
