use std::collections::{HashMap, BTreeMap};
use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List, LiteralValue};
use vm::types::{Value, PrincipalData, TypeSignature, TupleTypeSignature, FunctionArg, BUFF_32,
                FunctionType, FixedFunction, parse_name_type_pairs};
use vm::functions::{NativeFunctions, handle_binding_list, tuples};
use vm::functions::tuples::TupleDefinitionType::{Implicit, Explicit};
use vm::functions::define::DefineFunctionsParsed;
use vm::variables::NativeVariables;
use vm::MAX_CONTEXT_DEPTH;

use vm::analysis::AnalysisDatabase;
use super::{ContractAnalysis, AnalysisPass, TYPE_ANNOTATED_FAIL, CheckResult, CheckError,
            CheckErrors, CostOverflowingMath, ExecutionCost, CostFunctions, CostSpecification,
            SimpleCostSpecification, CostCounter, constants};
use super::common_costs::{get_hash_cost, get_binding_cost, get_function_lookup_cost};

pub enum SpecialCostType { ContractCall, If, Map, Filter, 
                           Fold, Let, TupleCons, TupleGet,
                           // these are special because the runtime cost is
                           //   associated with the _stored type_, not the arguments.
                           FetchVar, FetchEntry, FetchContractEntry,
                           // these are special because they only should measure
                           //   one of their arguments
                           SetVar, SetEntry, InsertEntry, DeleteEntry,
                           MintAsset, TransferAsset, GetAssetOwner
}

// note: this could be refactored to return static pointers.
pub fn get_native_function_cost_spec(func: &NativeFunctions) -> CostSpecification {
    use self::CostFunctions::{Constant, Linear};
    use vm::functions::NativeFunctions::*;

    let result = match func {
        ContractCall => { return CostSpecification::Special(SpecialCostType::ContractCall) },
        If =>           { return CostSpecification::Special(SpecialCostType::If) },
        Map =>          { return CostSpecification::Special(SpecialCostType::Map) },
        Filter =>       { return CostSpecification::Special(SpecialCostType::Filter) },
        Fold =>         { return CostSpecification::Special(SpecialCostType::Fold) },
        Let =>          { return CostSpecification::Special(SpecialCostType::Let) },
        TupleCons =>    { return CostSpecification::Special(SpecialCostType::TupleCons) },
        TupleGet =>     { return CostSpecification::Special(SpecialCostType::TupleGet) },
        Asserts =>  SimpleCostSpecification::new_diskless(Linear(constants::ASSERTS_COST_A,  constants::ASSERTS_COST_B)),

        // cost of arithmetics is linear in the number of arguments.
        Add =>      SimpleCostSpecification::new_diskless(Linear(constants::ADD_COST_A,      0)),
        Multiply => SimpleCostSpecification::new_diskless(Linear(constants::MULTIPLY_COST_A, 0)),
        Divide =>   SimpleCostSpecification::new_diskless(Linear(constants::DIVIDE_COST_A,   0)),
        Subtract => SimpleCostSpecification::new_diskless(Linear(constants::SUBTRACT_COST_A, 0)),

        // these arith. ops are _constant_ since they are of fixed length integers.
        CmpGeq | CmpLeq | CmpLess | CmpGreater =>
                        SimpleCostSpecification::new_diskless(Constant(constants::COMPARE_COST)),
        ToUInt | ToInt => 
                        SimpleCostSpecification::new_diskless(Constant(constants::INT_CAST_COST)),
        Modulo      =>  SimpleCostSpecification::new_diskless(Constant(constants::MOD_COST)),
        Power       =>  SimpleCostSpecification::new_diskless(Constant(constants::POW_COST)),
        BitwiseXOR  =>  SimpleCostSpecification::new_diskless(Constant(constants::XOR_COST)),

        And | Or => SimpleCostSpecification::new_diskless(Linear(constants::AND_OR_COST_A, 0)),

        Not => SimpleCostSpecification::new_diskless(Constant(constants::NOT_COST)),
        Equals => SimpleCostSpecification::new_diskless(Linear(constants::EQUALS_COST_A, 0)),

        // ensure this is a constant cost, since length is cached from list constructor.
        Len => SimpleCostSpecification::new_diskless(Constant(constants::LEN_COST)),

        ListCons => SimpleCostSpecification::new_diskless(Linear(constants::LIST_CONS_A, 0)),
        Begin => SimpleCostSpecification::new_diskless(Constant(constants::BEGIN_COST)),
        Sha512Trunc256 =>
                     SimpleCostSpecification::new_diskless(Linear(constants::SHA512T_A, constants::SHA512T_B)),
        Hash160 =>   SimpleCostSpecification::new_diskless(Linear(constants::HASH160_A, constants::HASH160_B)),
        Sha256 =>    SimpleCostSpecification::new_diskless(Linear(constants::SHA256_A,  constants::SHA256_B)),
        Sha512 =>    SimpleCostSpecification::new_diskless(Linear(constants::SHA512_A,  constants::SHA512_B)),
        Keccak256 => SimpleCostSpecification::new_diskless(Linear(constants::KECC256_A, constants::KECC256_B)),

        ConsSome | ConsOkay | ConsError 
                             => SimpleCostSpecification::new_diskless(Linear(constants::CONS_OPTION_A, constants::CONS_OPTION_B)),
        DefaultTo            => SimpleCostSpecification::new_diskless(Linear(constants::DEFAULT_TO_A,  constants::DEFAULT_TO_B)),
        Expects | ExpectsErr => SimpleCostSpecification::new_diskless(Linear(constants::EXPECTS_A,     constants::EXPECTS_B)),
        Print =>                SimpleCostSpecification::new_diskless(Linear(constants::PRINT_A, constants::PRINT_B)),

        IsOkay | IsNone => SimpleCostSpecification::new_diskless(Constant(constants::IS_OPTION_COST)),
        AsContract =>      SimpleCostSpecification::new_diskless(Constant(constants::AS_CONTRACT_COST)),

        // assert max len is linear right now due to clone.
        AssertsMaxLen => SimpleCostSpecification::new_diskless(Linear(constants::LEN_CHECK_A, constants::LEN_CHECK_B)),
        Concat => SimpleCostSpecification::new_diskless(Linear(constants::CONCAT_A, constants::CONCAT_B)),
        Append => SimpleCostSpecification::new_diskless(Linear(constants::APPEND_A, constants::APPEND_B)),

        // Fetches need to be handled specially.
        //    read runtime costs are linear (may be super-linear to parse) in the _stored type_, not the
        //      argument length
        FetchVar => { return CostSpecification::Special(SpecialCostType::FetchVar) },
        FetchEntry => { return CostSpecification::Special(SpecialCostType::FetchEntry) },
        FetchContractEntry => { return CostSpecification::Special(SpecialCostType::FetchContractEntry) },
        SetVar  => { return CostSpecification::Special(SpecialCostType::SetVar) },
        SetEntry => { return CostSpecification::Special(SpecialCostType::SetEntry) },
        InsertEntry => { return CostSpecification::Special(SpecialCostType::InsertEntry) },
        DeleteEntry => { return CostSpecification::Special(SpecialCostType::DeleteEntry) },
        GetBlockInfo => SimpleCostSpecification {
            read_count: Constant(1),
            read_length: Constant(constants::GET_BLOCK_INFO_READ_LEN),
            write_length: Constant(0), write_count: Constant(0),
            runtime: Constant(constants::GET_BLOCK_INFO_COST)
        },
        MintAsset => { return CostSpecification::Special(SpecialCostType::MintAsset) },
        TransferAsset => { return CostSpecification::Special(SpecialCostType::TransferAsset) },
        TransferToken => SimpleCostSpecification {
            read_count: Constant(1), write_count: Constant(1),
            read_length: Constant(constants::TRANSFER_TOKEN_READ_LEN),
            write_length: Constant(constants::TRANSFER_TOKEN_WRITE_LEN),
            runtime: Constant(constants::TRANSFER_TOKEN_COST),
        },
        MintToken => SimpleCostSpecification {
            read_count: Constant(1), write_count: Constant(1),            
            read_length: Constant(constants::MINT_TOKEN_READ_LEN),
            write_length: Constant(constants::MINT_TOKEN_WRITE_LEN),
            runtime: Constant(constants::MINT_TOKEN_COST),
        },
        GetTokenBalance => SimpleCostSpecification {
            read_count: Constant(1), read_length: Constant(constants::GET_TOKEN_BALANCE_READ_LEN),
            write_length: Constant(0), write_count: Constant(0),
            runtime: Constant(constants::GET_TOKEN_BALANCE_COST),
        },
        GetAssetOwner => { return CostSpecification::Special(SpecialCostType::GetAssetOwner) },
        AtBlock => SimpleCostSpecification {
            read_count: Constant(1), read_length: Constant(constants::AT_BLOCK_READ_LEN),
            write_length: Constant(0), write_count: Constant(0),
            runtime: Constant(constants::AT_BLOCK_COST),
        },
    };

    CostSpecification::Simple(result)
}

fn handle_special_tuple_cons<'a, 'b>(inst: &mut CostCounter<'a, 'b>, tuple_bindings: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
    let mut binding_cost = SimpleCostSpecification::new_diskless(
        CostFunctions::NLogN(constants::TUPLE_CONS_A, constants::TUPLE_CONS_B))
        .compute_cost(tuple_bindings.len() as u64)?;
    handle_binding_list(tuple_bindings, |var_name, var_sexp| {
        // the cost of binding the name.
        binding_cost.add(&get_binding_cost(var_name)?)?;

        // the cost of calculating the bound value
        binding_cost.add(
            &inst.handle_expression(var_sexp)?)
    })?;

    Ok(binding_cost)
}

fn handle_tuple_argument<'a, 'b>(inst: &mut CostCounter<'a, 'b>, arg: &SymbolicExpression) -> CheckResult<ExecutionCost> {
    match tuples::get_definition_type_of_tuple_argument(arg) {
        Explicit => inst.handle_expression(arg),
        Implicit(ref inner_expr) => handle_special_tuple_cons(inst, inner_expr)
    }
}

pub fn handle_special_function<'a, 'b>(inst: &mut CostCounter<'a, 'b>, function: &SpecialCostType, args: &[SymbolicExpression])
                                       -> CheckResult<ExecutionCost> {
    use self::CostFunctions::{Constant, Linear};
    use self::SpecialCostType::*;
    match function {
        // assert argument lengths, because this pass _must_ have occurred _after_
        //   other checks.
        ContractCall => {
            assert!(args.len() >= 2);

            let contract_id = match args[0].match_literal_value() {
                Some(Value::Principal(PrincipalData::Contract(ref contract_id))) => contract_id,
                _ => panic!("Contract call expects a contract principal")
            };
            let function_name = args[1].match_atom().expect("Function argument should have been atom.");
            let cost_spec = inst.db.get_contract_function_cost(&contract_id, function_name)
                .expect("Public function should exist");
            // BASE COST:
            //   RUNTIME = linear cost of the size of the called contract (the cost of parsing it out of the DB)
            //   READS = 1, 
            let base_cost = SimpleCostSpecification {
                write_length: CostFunctions::Constant(0),
                write_count: CostFunctions::Constant(0),
                read_count: CostFunctions::Constant(0),
                read_length: CostFunctions::Linear(1, 0),
                runtime: CostFunctions::Linear(constants::CONTRACT_CALL_RUNTIME_A,
                                               constants::CONTRACT_CALL_RUNTIME_B)
            };

            let mut total_cost = base_cost.compute_cost(
                inst.db.get_contract_size(&contract_id).expect("Contract should exist"))?;
            
            // add the cost of looking up the function within the contract
            total_cost.add(&get_function_lookup_cost(function_name)?)?;
            
            let arg_size = inst.handle_simple_function_args(&args[2..])?;
            let exec_cost = cost_spec.compute_cost(arg_size)?;
            
            total_cost.add(&exec_cost)?;
            
            Ok(total_cost)
        },
        If => {
            assert_eq!(args.len(), 3);

            let mut conditional_cost = inst.handle_expression(&args[0])?;
            let branch_1_cost = inst.handle_expression(&args[1])?;
            let branch_2_cost = inst.handle_expression(&args[2])?;

            conditional_cost.add(&ExecutionCost::max_cost(branch_1_cost, branch_2_cost))?;

            Ok(conditional_cost)
        },
        Map | Filter => {
            assert_eq!(args.len(), 2);

            let function_name = args[0].match_atom()
                .expect("Function argument should have been atom.");
            let (list_item_type, list_max_len) = match inst.type_map.get_type(&args[1]) {
                Some(TypeSignature::ListType(l)) => {
                    (l.get_list_item_type().clone(), l.get_max_len())
                },
                Some(TypeSignature::BufferType(buff_len)) => {
                    (TypeSignature::min_buffer(), u32::from(buff_len))
                },
                x => panic!("Expected list type, but annotated type was: {:#?}", x)
            };

            let function_spec = inst.cost_context.get_defined_function_cost_spec(function_name)
                .ok_or_else(|| CheckErrors::UnknownFunction(function_name.to_string()))?;
            let mut single_execution_cost = function_spec.compute_cost(list_item_type.size().into())?;

            single_execution_cost.multiply(list_max_len.into())?;

            // base cost: looking up function name in context.
            //   O(1) + O(function_name)
            single_execution_cost.add(&get_function_lookup_cost(function_name)?)?;

            Ok(single_execution_cost)
        },
        Fold => {
            assert_eq!(args.len(), 3);

            let function_name = args[0].match_atom()
                .expect("Function argument should have been atom.");

            let (list_item_type, list_max_len) = match inst.type_map.get_type(&args[1]) {
                Some(TypeSignature::ListType(l)) => {
                    (l.get_list_item_type().clone(), l.get_max_len())
                },
                Some(TypeSignature::BufferType(buff_len)) => {
                    (TypeSignature::min_buffer(), u32::from(buff_len))
                },
                x => panic!("Expected list type, but annotated type was: {:#?}", x)
            };


            let initial_value_type = inst.type_map.get_type(&args[2])
                .expect("Expected a type annotation");

            let function_spec = inst.cost_context.get_defined_function_cost_spec(function_name)
                .ok_or_else(|| CheckErrors::UnknownFunction(function_name.to_string()))?;

            let function_arg_len = u64::from(list_item_type.size())
                .cost_overflow_add(u64::from(initial_value_type.size()))?;

            let mut single_execution_cost = function_spec.compute_cost(function_arg_len)?;

            single_execution_cost.multiply(list_max_len.into())?;

            // base cost: looking up function name in context.
            //   O(1) + O(function_name)
            single_execution_cost.add(&get_function_lookup_cost(function_name)?)?;

            Ok(single_execution_cost)

        },
        Let => {
            assert!(args.len() >= 2);

            let bindings = args[0].match_list()
                .expect("Let expression must be supplied a binding list.");

            let mut binding_cost = ExecutionCost::runtime(constants::LET_CONSTANT_COST);

            handle_binding_list(bindings, |var_name, var_sexp| {
                // the cost of binding the name.
                binding_cost.add(&get_binding_cost(var_name)?)?;

                // the cost of calculating the bound value
                binding_cost.add(
                    &inst.handle_expression(var_sexp)?)
            })?;

            // evaluation of let bodies occur at context depth + 1.
            inst.cost_context.increment_context_depth()?;

            binding_cost.add(
                &inst.handle_all_expressions(&args[1..])?)?;

            inst.cost_context.decrement_context_depth();

            Ok(binding_cost)
        },
        TupleCons => {
            assert!(args.len() >= 1);

            handle_special_tuple_cons(inst, args)
        },
        TupleGet => {
            assert!(args.len() == 2);

            let tuple_length = match inst.type_map.get_type(&args[1]).expect(TYPE_ANNOTATED_FAIL) {
                TypeSignature::TupleType(tuple_data) => tuple_data.len(),
                TypeSignature::OptionalType(value_type) => {
                    if let TypeSignature::TupleType(ref tuple_data) = **value_type {
                        tuple_data.len()
                    } else {
                        panic!("Expected tuple type")
                    }
                }
                _ => panic!("Expected tuple type")
            };

            let var_name = args[0].match_atom().expect("Tuple get should be atom name.");

            // the cost of a tuple lookup is O(nlogn) --> tuples are implemented
            //   with btrees.
            let mut lookup_cost = SimpleCostSpecification::new_diskless(
                CostFunctions::NLogN(constants::TUPLE_LOOKUP_A, constants::TUPLE_LOOKUP_B))
                .compute_cost(tuple_length)?;
            // you always do a O(n) equality check on names in lookups.
            lookup_cost.add_runtime(var_name.len() as u64)?;

            Ok(lookup_cost)
        },
        FetchEntry => {
            assert!(args.len() == 2);
            let map_name = args[0].match_atom().expect("Argument should be atomic name.");
            let key_tuple = &args[1];

            let key_tuple_size = u64::from(inst.type_map.get_type(key_tuple)
                                           .expect(TYPE_ANNOTATED_FAIL)
                                           .size());
            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(map_name.len() as u64, key_tuple_size)?;

            // the cost of the database read...
            let value_tuple_size = u64::from(inst.analysis.get_map_type(map_name)
                                             .expect("Map should exist")
                                             .1.size());
            let read_cost = SimpleCostSpecification {
                read_count: Constant(1),
                read_length: Constant(value_tuple_size as u64),
                write_length: Constant(0), write_count: Constant(0),
                runtime: Linear(constants::LOOKUP_RUNTIME_COST_A, constants::LOOKUP_RUNTIME_COST_B),
            }.compute_cost(value_tuple_size)?;

            hash_cost.add(&read_cost)?;

            hash_cost.add(&handle_tuple_argument(inst, key_tuple)?)?;

            Ok(hash_cost)
        },
        FetchVar => {
            assert!(args.len() == 1);
            let var_name = args[0].match_atom().expect("Argument should be atomic name.");

            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(var_name.len() as u64, 0)?;

            // the cost of the database read...
            let value_size = u64::from(inst.analysis.get_persisted_variable_type(var_name)
                                       .expect("Variable should exist").size());
            let read_cost = SimpleCostSpecification {
                read_count: Constant(1),
                read_length: Constant(value_size as u64),
                write_length: Constant(0), write_count: Constant(0),
                runtime: Linear(constants::LOOKUP_RUNTIME_COST_A, constants::LOOKUP_RUNTIME_COST_B),
            }.compute_cost(value_size)?;

            hash_cost.add(&read_cost)?;

            Ok(hash_cost)
        },
        FetchContractEntry => {
            assert!(args.len() == 3);
            let contract = match args[0].match_literal_value() {
                Some(Value::Principal(PrincipalData::Contract(x))) => x,
                _ => panic!("Argument should be literal contract identifier")
            };

            let map_name = args[1].match_atom().expect("Argument should be atomic name.");
            let key_tuple = &args[2];

            let key_tuple_size = u64::from(inst.type_map.get_type(key_tuple).expect(TYPE_ANNOTATED_FAIL)
                                           .size());
            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(map_name.len() as u64, key_tuple_size)?;

            // the cost of the database read...
            let value_tuple_size = u64::from(inst.db.get_map_type(contract, map_name)
                                             .expect("Map should exist")
                                             .1.size());
            let read_cost = SimpleCostSpecification {
                read_count: Constant(1),
                read_length: Constant(value_tuple_size as u64),
                write_length: Constant(0), write_count: Constant(0),
                runtime: Linear(constants::LOOKUP_RUNTIME_COST_A, constants::LOOKUP_RUNTIME_COST_B),
            }.compute_cost(value_tuple_size)?;

            hash_cost.add(&handle_tuple_argument(inst, key_tuple)?)?;

            hash_cost.add(&read_cost)?;

            Ok(hash_cost)
        },
        SetVar => {
            assert!(args.len() == 2);
            let var_name = args[0].match_atom().expect("Argument should be atomic name.");
            let value_arg = &args[1];
            let value_size =  u64::from(inst.type_map.get_type(value_arg)
                                        .expect(TYPE_ANNOTATED_FAIL)
                                        .size());

            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(var_name.len() as u64, 0)?;

            // the cost of the database op...
            let write_cost = SimpleCostSpecification {
                read_count: Constant(0), read_length: Constant(0),
                write_length: Constant(value_size), write_count: Constant(1),
                runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
            }.compute_cost(value_size)?;

            hash_cost.add(&write_cost)?;

            // the cost of computing the value arg
            hash_cost.add(&inst.handle_expression(value_arg)?)?;

            Ok(hash_cost)
        },
        SetEntry => {
            assert!(args.len() == 3);
            let map_name = args[0].match_atom().expect("Argument should be atomic name.");
            let key_tuple = &args[1];
            let value_tuple = &args[2];

            let value_size =  u64::from(inst.type_map.get_type(value_tuple)
                                        .expect(TYPE_ANNOTATED_FAIL)
                                        .size());

            let key_size =  u64::from(inst.type_map.get_type(key_tuple)
                                      .expect(TYPE_ANNOTATED_FAIL)
                                      .size());
            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(map_name.len() as u64, key_size)?;

            // the cost of the database op...
            let write_cost = SimpleCostSpecification {
                read_count: Constant(0), read_length: Constant(0),
                write_length: Constant(value_size), write_count: Constant(1),
                runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
            }.compute_cost(value_size)?;

            hash_cost.add(&write_cost)?;

            // the cost of computing the key, value args
            hash_cost.add(&handle_tuple_argument(inst, key_tuple)?)?;
            hash_cost.add(&handle_tuple_argument(inst, value_tuple)?)?;

            Ok(hash_cost)
        },
        InsertEntry => {
            assert!(args.len() == 3);
            let map_name = args[0].match_atom().expect("Argument should be atomic name.");
            let key_tuple = &args[1];
            let value_tuple = &args[2];

            let value_size =  u64::from(inst.type_map.get_type(value_tuple)
                                        .expect(TYPE_ANNOTATED_FAIL)
                                        .size());

            let key_size =  u64::from(inst.type_map.get_type(key_tuple)
                                      .expect(TYPE_ANNOTATED_FAIL)
                                      .size());
            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(map_name.len() as u64, key_size)?;

            // the cost of the database op...
            let write_cost = SimpleCostSpecification {
                read_count: Constant(1), read_length: Constant(0),
                write_length: Constant(value_size), write_count: Constant(1),
                runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
            }.compute_cost(value_size)?;

            hash_cost.add(&write_cost)?;

            // the cost of computing the key, value args
            hash_cost.add(&handle_tuple_argument(inst, key_tuple)?)?;
            hash_cost.add(&handle_tuple_argument(inst, value_tuple)?)?;

            Ok(hash_cost)
        },
        DeleteEntry => {
            assert!(args.len() == 2);
            let map_name = args[0].match_atom().expect("Argument should be atomic name.");
            let key_tuple = &args[1];

            let key_size =  u64::from(inst.type_map.get_type(key_tuple)
                                      .expect(TYPE_ANNOTATED_FAIL)
                                      .size());
            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(map_name.len() as u64, key_size)?;

            // the cost of the database op...
            let write_cost = SimpleCostSpecification {
                read_count: Constant(1), read_length: Constant(0),
                write_length: Constant(1), write_count: Constant(1),
                runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
            }.compute_cost(1)?;

            hash_cost.add(&write_cost)?;

            // the cost of computing the key, value args
            hash_cost.add(&handle_tuple_argument(inst, key_tuple)?)?;

            Ok(hash_cost)
        },
        MintAsset => {
            assert!(args.len() == 3);
            let asset_name = args[0].match_atom().expect("Argument should be atomic name.");
            let asset_key = &args[1];
            let asset_owner = &args[2];

            let key_size =  u64::from(inst.type_map.get_type(asset_key)
                                      .expect(TYPE_ANNOTATED_FAIL)
                                      .size());
            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(asset_name.len() as u64, key_size)?;

            // the cost of the database op...
            let write_cost = SimpleCostSpecification {
                read_count: Constant(1), read_length: Linear(1, 0),
                write_count: Constant(1), write_length: Linear(1, 0),
                runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
            }.compute_cost(constants::ASSET_OWNER_LENGTH)?;

            hash_cost.add(&write_cost)?;

            // the cost of computing the key, value args
            hash_cost.add(&inst.handle_expression(asset_key)?)?;
            hash_cost.add(&inst.handle_expression(asset_owner)?)?;

            Ok(hash_cost)
        },
        TransferAsset => {
            assert!(args.len() == 4);
            let asset_name = args[0].match_atom().expect("Argument should be atomic name.");
            let asset_key = &args[1];
            let asset_sender = &args[2];
            let asset_receiver = &args[3];

            let key_size =  u64::from(inst.type_map.get_type(asset_key)
                                      .expect(TYPE_ANNOTATED_FAIL)
                                      .size());
            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(asset_name.len() as u64, key_size)?;
            // you do two lookups
            hash_cost.multiply(2)?;

            // the cost of the database ops...
            let write_cost = SimpleCostSpecification {
                read_count: Constant(1), read_length: Linear(1, 0),
                write_count: Constant(1), write_length: Linear(1, 0),
                runtime: Linear(2*constants::DB_WRITE_RUNTIME_COST_A, 2*constants::DB_WRITE_RUNTIME_COST_B),
            }.compute_cost(constants::ASSET_OWNER_LENGTH)?;

            hash_cost.add(&write_cost)?;

            // the cost of computing the key, value args
            hash_cost.add(&inst.handle_expression(asset_key)?)?;
            hash_cost.add(&inst.handle_expression(asset_sender)?)?;
            hash_cost.add(&inst.handle_expression(asset_receiver)?)?;

            Ok(hash_cost)
        },
        GetAssetOwner => {
            assert!(args.len() == 2);
            let asset_name = args[0].match_atom().expect("Argument should be atomic name.");
            let asset_key = &args[1];

            let key_size =  u64::from(inst.type_map.get_type(asset_key)
                                      .expect(TYPE_ANNOTATED_FAIL)
                                      .size());
            // the cost of the hash lookup...
            let mut hash_cost = get_hash_cost(asset_name.len() as u64, key_size)?;

            // the cost of the database ops...
            let write_cost = SimpleCostSpecification {
                read_count: Constant(1), read_length: Linear(1, 0),
                write_count: Constant(0), write_length: Constant(0),
                runtime: Linear(constants::LOOKUP_RUNTIME_COST_A, constants::LOOKUP_RUNTIME_COST_B),
            }.compute_cost(constants::ASSET_OWNER_LENGTH)?;

            hash_cost.add(&write_cost)?;

            // the cost of computing the key, value args
            hash_cost.add(&inst.handle_expression(asset_key)?)?;

            Ok(hash_cost)
        },
    }
}
