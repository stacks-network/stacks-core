use std::{borrow::BorrowMut, collections::HashMap, fs::File, io::Write};

use wasmtime::{AsContextMut, Caller, Engine, Linker, Memory, Module, Store, Trap, Val};

use super::{
    analysis::CheckErrors,
    callables::{DefineType, DefinedFunction},
    contracts::Contract,
    costs::CostTracker,
    database::{clarity_db::ValueResult, ClarityDatabase, DataVariableMetadata, STXBalance},
    errors::RuntimeErrorType,
    events::*,
    types::{
        AssetIdentifier, BuffData, CharType, FixedFunction, FunctionType, PrincipalData,
        QualifiedContractIdentifier, SequenceData, StandardPrincipalData, TupleData,
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
        .instantiate(store.as_context_mut(), &module)
        .map_err(|e| Error::Wasm(WasmError::UnableToLoadModule(e)))?;

    // Call the `.defines` function, which contains all define-* expressions
    // from the contract.
    let defines_func = instance
        .get_func(store.as_context_mut(), ".top-level")
        .ok_or(Error::Wasm(WasmError::DefinesNotFound))?;
    let mut define_results = [];

    defines_func
        .call(store.as_context_mut(), &[], &mut define_results)
        .map_err(|e| Error::Wasm(WasmError::Runtime(e)))?;

    // Save the compiled Wasm module into the contract context
    store.data_mut().contract_context_mut()?.set_wasm_module(
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

/// Read an identifier (string) from the WASM memory at `offset` with `length`.
fn read_identifier_from_wasm<T>(
    caller: &mut Caller<'_, T>,
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
fn read_from_wasm<T>(
    caller: &mut Caller<'_, T>,
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
            let mut buffer: Vec<u8> = vec![0; length as usize];
            memory
                .read(caller, offset as usize, &mut buffer)
                .map_err(|e| Error::Wasm(WasmError::Runtime(e.into())))?;
            Value::buff_from(buffer)
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

fn value_as_buffer(value: Value) -> Result<BuffData, Error> {
    match value {
        Value::Sequence(SequenceData::Buffer(buffdata)) => Ok(buffdata),
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
        TypeSignature::SequenceType(SequenceSubtype::BufferType(buffer_length)) => {
            let length: u32 = buffer_length.into();
            // Return values will be offset and length
            Ok((vec![Val::I32(0), Val::I32(0)], offset + length as i32))
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
        TypeSignature::SequenceType(SequenceSubtype::BufferType(_buffer_length)) => {
            let offset = buffer[value_index]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let length = buffer[value_index + 1]
                .i32()
                .ok_or(Error::Wasm(WasmError::ValueTypeMismatch))?;
            let mut buff: Vec<u8> = vec![0; length as usize];
            memory
                .read(store.borrow_mut(), offset as usize, &mut buff)
                .map_err(|e| Error::Wasm(WasmError::UnableToReadMemory(e.into())))?;
            Ok((Some(Value::buff_from(buff)?), 2))
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

/// Link the host interface functions for into the Wasm module.
fn link_host_functions(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    link_define_function_fn(linker)?;
    link_define_variable_fn(linker)?;
    link_define_ft_fn(linker)?;
    link_define_nft_fn(linker)?;

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

/// Link host interface function, `define_variable`, into the Wasm module.
/// This function is called for all variable definitions (`define-data-var`).
fn link_define_variable_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "define_variable",
            |mut caller: Caller<'_, ClarityWasmContext>, name_offset: i32, name_length: i32| {
                // TODO: Include this cost
                // runtime_cost(ClarityCostFunction::CreateVar, global_context, value_type.size())?;

                // Read the variable name string from the memory
                let name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;

                // Retrieve the type of this variable
                let value_type = caller
                    .data()
                    .contract_analysis
                    .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
                    .get_persisted_variable_type(name.as_str())
                    .ok_or(Error::Unchecked(CheckErrors::DefineVariableBadSignature))?
                    .clone();

                let contract = caller.data().contract_context().contract_identifier.clone();

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
                    .add_memory(value_type.size() as u64)
                    .map_err(|e| Error::from(e))?;

                // Create the variable in the global context
                let data_types = caller.data_mut().global_context.database.create_variable(
                    &contract,
                    name.as_str(),
                    value_type,
                );

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
                let name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;
                let cname = ClarityName::try_from(name.clone())?;

                let total_supply = if supply_indicator == 1 {
                    Some(((supply_hi as u128) << 64) | supply_lo as u128)
                } else {
                    None
                };

                // runtime_cost(ClarityCostFunction::CreateFt, global_context, 0)?;

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

                let contract_identifier = caller
                    .data_mut()
                    .contract_context()
                    .contract_identifier
                    .clone();
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
                let name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;
                let cname = ClarityName::try_from(name.clone())?;

                // Get the type of this NFT from the contract analysis
                let asset_type = caller
                    .data()
                    .contract_analysis
                    .ok_or(Error::Wasm(WasmError::DefineFunctionCalledInRunMode))?
                    .non_fungible_tokens
                    .get(&cname)
                    .ok_or(Error::Unchecked(CheckErrors::DefineNFTBadSignature))?;

                // runtime_cost(ClarityCostFunction::CreateNft, global_context, asset_type.size())?;

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

                let contract_identifier = caller
                    .data_mut()
                    .contract_context()
                    .contract_identifier
                    .clone();

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
                // Retrieve the variable name for this identifier
                let var_name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;

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
                // Retrieve the variable name for this identifier
                let var_name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;

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
            |mut caller: Caller<'_, ClarityWasmContext>, return_offset: i32, return_length: i32| {
                let sender = caller.data().sender.clone().ok_or(Error::Runtime(
                    RuntimeErrorType::NoSenderInContext.into(),
                    None,
                ))?;

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
fn link_contract_caller_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "contract_caller",
            |mut caller: Caller<'_, ClarityWasmContext>, return_offset: i32, return_length: i32| {
                let contract_caller = caller.data().caller.clone().ok_or(Error::Runtime(
                    RuntimeErrorType::NoCallerInContext.into(),
                    None,
                ))?;

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
fn link_tx_sponsor_fn(linker: &mut Linker<ClarityWasmContext>) -> Result<(), Error> {
    linker
        .func_wrap(
            "clarity",
            "tx_sponsor",
            |mut caller: Caller<'_, ClarityWasmContext>, return_offset: i32, return_length: i32| {
                let opt_sponsor = caller.data().sponsor.clone();
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
                // Read the principal from the Wasm memory
                let value = read_from_wasm(
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
                // Read the principal from the Wasm memory
                let value = read_from_wasm(
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

                // Read the principal from the Wasm memory
                let value = read_from_wasm(
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

                // Read the sender principal from the Wasm memory
                let value = read_from_wasm(
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    sender_offset,
                    sender_length,
                )?;
                let sender = value_as_principal(&value)?;

                // Read the to principal from the Wasm memory
                let value = read_from_wasm(
                    &mut caller,
                    &TypeSignature::PrincipalType,
                    recipient_offset,
                    recipient_length,
                )?;
                let recipient = value_as_principal(&value)?;

                // Read the memo from the Wasm memory
                let memo = if memo_length > 0 {
                    let value = read_from_wasm(
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
                // Retrieve the token name
                let token_name = read_identifier_from_wasm(&mut caller, name_offset, name_length)?;

                let contract_identifier =
                    caller.data().contract_context().contract_identifier.clone();

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
