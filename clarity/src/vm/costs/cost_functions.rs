// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use super::ExecutionCost;
use crate::vm::errors::{InterpreterResult, RuntimeErrorType};

define_named_enum!(ClarityCostFunction {
    AnalysisTypeAnnotate("cost_analysis_type_annotate"),
    AnalysisTypeCheck("cost_analysis_type_check"),
    AnalysisTypeLookup("cost_analysis_type_lookup"),
    AnalysisVisit("cost_analysis_visit"),
    AnalysisIterableFunc("cost_analysis_iterable_func"),
    AnalysisOptionCons("cost_analysis_option_cons"),
    AnalysisOptionCheck("cost_analysis_option_check"),
    AnalysisBindName("cost_analysis_bind_name"),
    AnalysisListItemsCheck("cost_analysis_list_items_check"),
    AnalysisCheckTupleGet("cost_analysis_check_tuple_get"),
    AnalysisCheckTupleMerge("cost_analysis_check_tuple_merge"),
    AnalysisCheckTupleCons("cost_analysis_check_tuple_cons"),
    AnalysisTupleItemsCheck("cost_analysis_tuple_items_check"),
    AnalysisCheckLet("cost_analysis_check_let"),
    AnalysisLookupFunction("cost_analysis_lookup_function"),
    AnalysisLookupFunctionTypes("cost_analysis_lookup_function_types"),
    AnalysisLookupVariableConst("cost_analysis_lookup_variable_const"),
    AnalysisLookupVariableDepth("cost_analysis_lookup_variable_depth"),
    AstParse("cost_ast_parse"),
    AstCycleDetection("cost_ast_cycle_detection"),
    AnalysisStorage("cost_analysis_storage"),
    AnalysisUseTraitEntry("cost_analysis_use_trait_entry"),
    AnalysisGetFunctionEntry("cost_analysis_get_function_entry"),
    AnalysisFetchContractEntry("cost_analysis_fetch_contract_entry"),
    LookupVariableDepth("cost_lookup_variable_depth"),
    LookupVariableSize("cost_lookup_variable_size"),
    LookupFunction("cost_lookup_function"),
    BindName("cost_bind_name"),
    InnerTypeCheckCost("cost_inner_type_check_cost"),
    UserFunctionApplication("cost_user_function_application"),
    Let("cost_let"),
    If("cost_if"),
    Asserts("cost_asserts"),
    Map("cost_map"),
    Filter("cost_filter"),
    Len("cost_len"),
    ElementAt("cost_element_at"),
    IndexOf("cost_index_of"),
    Fold("cost_fold"),
    ListCons("cost_list_cons"),
    TypeParseStep("cost_type_parse_step"),
    TupleGet("cost_tuple_get"),
    TupleMerge("cost_tuple_merge"),
    TupleCons("cost_tuple_cons"),
    Add("cost_add"),
    Sub("cost_sub"),
    Mul("cost_mul"),
    Div("cost_div"),
    Geq("cost_geq"),
    Leq("cost_leq"),
    Le("cost_le"),
    Ge("cost_ge"),
    IntCast("cost_int_cast"),
    Mod("cost_mod"),
    Pow("cost_pow"),
    Sqrti("cost_sqrti"),
    Log2("cost_log2"),
    Xor("cost_xor"),
    Not("cost_not"),
    Eq("cost_eq"),
    Begin("cost_begin"),
    Hash160("cost_hash160"),
    Sha256("cost_sha256"),
    Sha512("cost_sha512"),
    Sha512t256("cost_sha512t256"),
    Keccak256("cost_keccak256"),
    Secp256k1recover("cost_secp256k1recover"),
    Secp256k1verify("cost_secp256k1verify"),
    Print("cost_print"),
    SomeCons("cost_some_cons"),
    OkCons("cost_ok_cons"),
    ErrCons("cost_err_cons"),
    DefaultTo("cost_default_to"),
    UnwrapRet("cost_unwrap_ret"),
    UnwrapErrOrRet("cost_unwrap_err_or_ret"),
    IsOkay("cost_is_okay"),
    IsNone("cost_is_none"),
    IsErr("cost_is_err"),
    IsSome("cost_is_some"),
    Unwrap("cost_unwrap"),
    UnwrapErr("cost_unwrap_err"),
    TryRet("cost_try_ret"),
    Match("cost_match"),
    Or("cost_or"),
    And("cost_and"),
    Append("cost_append"),
    Concat("cost_concat"),
    AsMaxLen("cost_as_max_len"),
    ContractCall("cost_contract_call"),
    ContractOf("cost_contract_of"),
    PrincipalOf("cost_principal_of"),
    AtBlock("cost_at_block"),
    LoadContract("cost_load_contract"),
    CreateMap("cost_create_map"),
    CreateVar("cost_create_var"),
    CreateNft("cost_create_nft"),
    CreateFt("cost_create_ft"),
    FetchEntry("cost_fetch_entry"),
    SetEntry("cost_set_entry"),
    FetchVar("cost_fetch_var"),
    SetVar("cost_set_var"),
    ContractStorage("cost_contract_storage"),
    BlockInfo("cost_block_info"),
    StxBalance("cost_stx_balance"),
    StxTransfer("cost_stx_transfer"),
    FtMint("cost_ft_mint"),
    FtTransfer("cost_ft_transfer"),
    FtBalance("cost_ft_balance"),
    FtSupply("cost_ft_get_supply"),
    FtBurn("cost_ft_burn"),
    NftMint("cost_nft_mint"),
    NftTransfer("cost_nft_transfer"),
    NftOwner("cost_nft_owner"),
    NftBurn("cost_nft_burn"),
    PoisonMicroblock("poison_microblock"),
    BuffToIntLe("cost_buff_to_int_le"),
    BuffToUIntLe("cost_buff_to_uint_le"),
    BuffToIntBe("cost_buff_to_int_be"),
    BuffToUIntBe("cost_buff_to_uint_be"),
    IsStandard("cost_is_standard"),
    PrincipalDestruct("cost_principal_destruct"),
    PrincipalConstruct("cost_principal_construct"),
    StringToInt("cost_string_to_int"),
    StringToUInt("cost_string_to_uint"),
    IntToAscii("cost_int_to_ascii"),
    IntToUtf8("cost_int_to_utf8"),
    GetBurnBlockInfo("cost_burn_block_info"),
    StxGetAccount("cost_stx_account"),
    Slice("cost_slice"),
    ToConsensusBuff("cost_to_consensus_buff"),
    FromConsensusBuff("cost_from_consensus_buff"),
    StxTransferMemo("cost_stx_transfer_memo"),
    ReplaceAt("cost_replace_at"),
    AsContract("cost_as_contract"),
    BitwiseAnd("cost_bitwise_and"),
    BitwiseOr("cost_bitwise_or"),
    BitwiseNot("cost_bitwise_not"),
    BitwiseLShift("cost_bitwise_left_shift"),
    BitwiseRShift("cost_bitwise_right_shift"),
    Unimplemented("cost_unimplemented"),
});

// Helper functions used by `CostValues` implementations

pub fn linear(n: u64, a: u64, b: u64) -> u64 {
    a.saturating_mul(n).saturating_add(b)
}
pub fn logn(n: u64, a: u64, b: u64) -> InterpreterResult<u64> {
    if n < 1 {
        return Err(crate::vm::errors::Error::Runtime(
            RuntimeErrorType::Arithmetic("log2 must be passed a positive integer".to_string()),
            Some(vec![]),
        ));
    }
    let nlog2 = u64::from(64 - 1 - n.leading_zeros());
    Ok(a.saturating_mul(nlog2).saturating_add(b))
}
pub fn nlogn(n: u64, a: u64, b: u64) -> InterpreterResult<u64> {
    if n < 1 {
        return Err(crate::vm::errors::Error::Runtime(
            RuntimeErrorType::Arithmetic("log2 must be passed a positive integer".to_string()),
            Some(vec![]),
        ));
    }
    let nlog2 = u64::from(64 - 1 - n.leading_zeros());
    Ok(a.saturating_mul(nlog2.saturating_mul(n)).saturating_add(b))
}

pub trait CostValues {
    fn cost_analysis_type_annotate(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_type_check(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_type_lookup(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_visit(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_iterable_func(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_option_cons(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_option_check(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_bind_name(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_list_items_check(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_check_tuple_get(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_check_tuple_merge(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_check_tuple_cons(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_tuple_items_check(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_check_let(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_lookup_function(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_lookup_function_types(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_lookup_variable_const(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_lookup_variable_depth(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ast_parse(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ast_cycle_detection(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_storage(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_use_trait_entry(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_get_function_entry(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_analysis_fetch_contract_entry(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_lookup_variable_depth(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_lookup_variable_size(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_lookup_function(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_bind_name(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_inner_type_check_cost(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_user_function_application(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_let(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_if(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_asserts(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_map(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_filter(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_len(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_element_at(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_index_of(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_fold(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_list_cons(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_type_parse_step(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_tuple_get(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_tuple_merge(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_tuple_cons(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_add(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_sub(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_mul(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_div(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_geq(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_leq(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_le(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ge(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_int_cast(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_mod(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_pow(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_sqrti(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_log2(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_xor(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_not(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_eq(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_begin(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_hash160(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_sha256(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_sha512(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_sha512t256(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_keccak256(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_secp256k1recover(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_secp256k1verify(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_print(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_some_cons(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ok_cons(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_err_cons(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_default_to(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_unwrap_ret(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_unwrap_err_or_ret(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_is_okay(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_is_none(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_is_err(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_is_some(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_unwrap(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_unwrap_err(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_try_ret(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_match(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_or(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_and(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_append(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_concat(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_as_max_len(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_contract_call(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_contract_of(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_principal_of(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_at_block(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_load_contract(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_create_map(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_create_var(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_create_nft(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_create_ft(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_fetch_entry(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_set_entry(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_fetch_var(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_set_var(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_contract_storage(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_block_info(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_stx_balance(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_stx_transfer(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ft_mint(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ft_transfer(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ft_balance(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ft_get_supply(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_ft_burn(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_nft_mint(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_nft_transfer(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_nft_owner(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_nft_burn(n: u64) -> InterpreterResult<ExecutionCost>;
    fn poison_microblock(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_buff_to_int_le(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_buff_to_uint_le(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_buff_to_int_be(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_buff_to_uint_be(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_is_standard(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_principal_destruct(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_principal_construct(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_string_to_int(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_string_to_uint(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_int_to_ascii(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_int_to_utf8(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_burn_block_info(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_stx_account(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_slice(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_to_consensus_buff(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_from_consensus_buff(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_stx_transfer_memo(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_replace_at(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_as_contract(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_bitwise_and(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_bitwise_or(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_bitwise_not(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_bitwise_left_shift(n: u64) -> InterpreterResult<ExecutionCost>;
    fn cost_bitwise_right_shift(n: u64) -> InterpreterResult<ExecutionCost>;
}

impl ClarityCostFunction {
    pub fn eval<C: CostValues>(&self, n: u64) -> InterpreterResult<ExecutionCost> {
        match self {
            ClarityCostFunction::AnalysisTypeAnnotate => C::cost_analysis_type_annotate(n),
            ClarityCostFunction::AnalysisTypeCheck => C::cost_analysis_type_check(n),
            ClarityCostFunction::AnalysisTypeLookup => C::cost_analysis_type_lookup(n),
            ClarityCostFunction::AnalysisVisit => C::cost_analysis_visit(n),
            ClarityCostFunction::AnalysisIterableFunc => C::cost_analysis_iterable_func(n),
            ClarityCostFunction::AnalysisOptionCons => C::cost_analysis_option_cons(n),
            ClarityCostFunction::AnalysisOptionCheck => C::cost_analysis_option_check(n),
            ClarityCostFunction::AnalysisBindName => C::cost_analysis_bind_name(n),
            ClarityCostFunction::AnalysisListItemsCheck => C::cost_analysis_list_items_check(n),
            ClarityCostFunction::AnalysisCheckTupleGet => C::cost_analysis_check_tuple_get(n),
            ClarityCostFunction::AnalysisCheckTupleMerge => C::cost_analysis_check_tuple_merge(n),
            ClarityCostFunction::AnalysisCheckTupleCons => C::cost_analysis_check_tuple_cons(n),
            ClarityCostFunction::AnalysisTupleItemsCheck => C::cost_analysis_tuple_items_check(n),
            ClarityCostFunction::AnalysisCheckLet => C::cost_analysis_check_let(n),
            ClarityCostFunction::AnalysisLookupFunction => C::cost_analysis_lookup_function(n),
            ClarityCostFunction::AnalysisLookupFunctionTypes => {
                C::cost_analysis_lookup_function_types(n)
            }
            ClarityCostFunction::AnalysisLookupVariableConst => {
                C::cost_analysis_lookup_variable_const(n)
            }
            ClarityCostFunction::AnalysisLookupVariableDepth => {
                C::cost_analysis_lookup_variable_depth(n)
            }
            ClarityCostFunction::AstParse => C::cost_ast_parse(n),
            ClarityCostFunction::AstCycleDetection => C::cost_ast_cycle_detection(n),
            ClarityCostFunction::AnalysisStorage => C::cost_analysis_storage(n),
            ClarityCostFunction::AnalysisUseTraitEntry => C::cost_analysis_use_trait_entry(n),
            ClarityCostFunction::AnalysisGetFunctionEntry => C::cost_analysis_get_function_entry(n),
            ClarityCostFunction::AnalysisFetchContractEntry => {
                C::cost_analysis_fetch_contract_entry(n)
            }
            ClarityCostFunction::LookupVariableDepth => C::cost_lookup_variable_depth(n),
            ClarityCostFunction::LookupVariableSize => C::cost_lookup_variable_size(n),
            ClarityCostFunction::LookupFunction => C::cost_lookup_function(n),
            ClarityCostFunction::BindName => C::cost_bind_name(n),
            ClarityCostFunction::InnerTypeCheckCost => C::cost_inner_type_check_cost(n),
            ClarityCostFunction::UserFunctionApplication => C::cost_user_function_application(n),
            ClarityCostFunction::Let => C::cost_let(n),
            ClarityCostFunction::If => C::cost_if(n),
            ClarityCostFunction::Asserts => C::cost_asserts(n),
            ClarityCostFunction::Map => C::cost_map(n),
            ClarityCostFunction::Filter => C::cost_filter(n),
            ClarityCostFunction::Len => C::cost_len(n),
            ClarityCostFunction::ElementAt => C::cost_element_at(n),
            ClarityCostFunction::IndexOf => C::cost_index_of(n),
            ClarityCostFunction::Fold => C::cost_fold(n),
            ClarityCostFunction::ListCons => C::cost_list_cons(n),
            ClarityCostFunction::TypeParseStep => C::cost_type_parse_step(n),
            ClarityCostFunction::TupleGet => C::cost_tuple_get(n),
            ClarityCostFunction::TupleMerge => C::cost_tuple_merge(n),
            ClarityCostFunction::TupleCons => C::cost_tuple_cons(n),
            ClarityCostFunction::Add => C::cost_add(n),
            ClarityCostFunction::Sub => C::cost_sub(n),
            ClarityCostFunction::Mul => C::cost_mul(n),
            ClarityCostFunction::Div => C::cost_div(n),
            ClarityCostFunction::Geq => C::cost_geq(n),
            ClarityCostFunction::Leq => C::cost_leq(n),
            ClarityCostFunction::Le => C::cost_le(n),
            ClarityCostFunction::Ge => C::cost_ge(n),
            ClarityCostFunction::IntCast => C::cost_int_cast(n),
            ClarityCostFunction::Mod => C::cost_mod(n),
            ClarityCostFunction::Pow => C::cost_pow(n),
            ClarityCostFunction::Sqrti => C::cost_sqrti(n),
            ClarityCostFunction::Log2 => C::cost_log2(n),
            ClarityCostFunction::Xor => C::cost_xor(n),
            ClarityCostFunction::Not => C::cost_not(n),
            ClarityCostFunction::Eq => C::cost_eq(n),
            ClarityCostFunction::Begin => C::cost_begin(n),
            ClarityCostFunction::Hash160 => C::cost_hash160(n),
            ClarityCostFunction::Sha256 => C::cost_sha256(n),
            ClarityCostFunction::Sha512 => C::cost_sha512(n),
            ClarityCostFunction::Sha512t256 => C::cost_sha512t256(n),
            ClarityCostFunction::Keccak256 => C::cost_keccak256(n),
            ClarityCostFunction::Secp256k1recover => C::cost_secp256k1recover(n),
            ClarityCostFunction::Secp256k1verify => C::cost_secp256k1verify(n),
            ClarityCostFunction::Print => C::cost_print(n),
            ClarityCostFunction::SomeCons => C::cost_some_cons(n),
            ClarityCostFunction::OkCons => C::cost_ok_cons(n),
            ClarityCostFunction::ErrCons => C::cost_err_cons(n),
            ClarityCostFunction::DefaultTo => C::cost_default_to(n),
            ClarityCostFunction::UnwrapRet => C::cost_unwrap_ret(n),
            ClarityCostFunction::UnwrapErrOrRet => C::cost_unwrap_err_or_ret(n),
            ClarityCostFunction::IsOkay => C::cost_is_okay(n),
            ClarityCostFunction::IsNone => C::cost_is_none(n),
            ClarityCostFunction::IsErr => C::cost_is_err(n),
            ClarityCostFunction::IsSome => C::cost_is_some(n),
            ClarityCostFunction::Unwrap => C::cost_unwrap(n),
            ClarityCostFunction::UnwrapErr => C::cost_unwrap_err(n),
            ClarityCostFunction::TryRet => C::cost_try_ret(n),
            ClarityCostFunction::Match => C::cost_match(n),
            ClarityCostFunction::Or => C::cost_or(n),
            ClarityCostFunction::And => C::cost_and(n),
            ClarityCostFunction::Append => C::cost_append(n),
            ClarityCostFunction::Concat => C::cost_concat(n),
            ClarityCostFunction::AsMaxLen => C::cost_as_max_len(n),
            ClarityCostFunction::ContractCall => C::cost_contract_call(n),
            ClarityCostFunction::ContractOf => C::cost_contract_of(n),
            ClarityCostFunction::PrincipalOf => C::cost_principal_of(n),
            ClarityCostFunction::AtBlock => C::cost_at_block(n),
            ClarityCostFunction::LoadContract => C::cost_load_contract(n),
            ClarityCostFunction::CreateMap => C::cost_create_map(n),
            ClarityCostFunction::CreateVar => C::cost_create_var(n),
            ClarityCostFunction::CreateNft => C::cost_create_nft(n),
            ClarityCostFunction::CreateFt => C::cost_create_ft(n),
            ClarityCostFunction::FetchEntry => C::cost_fetch_entry(n),
            ClarityCostFunction::SetEntry => C::cost_set_entry(n),
            ClarityCostFunction::FetchVar => C::cost_fetch_var(n),
            ClarityCostFunction::SetVar => C::cost_set_var(n),
            ClarityCostFunction::ContractStorage => C::cost_contract_storage(n),
            ClarityCostFunction::BlockInfo => C::cost_block_info(n),
            ClarityCostFunction::StxBalance => C::cost_stx_balance(n),
            ClarityCostFunction::StxTransfer => C::cost_stx_transfer(n),
            ClarityCostFunction::FtMint => C::cost_ft_mint(n),
            ClarityCostFunction::FtTransfer => C::cost_ft_transfer(n),
            ClarityCostFunction::FtBalance => C::cost_ft_balance(n),
            ClarityCostFunction::FtSupply => C::cost_ft_get_supply(n),
            ClarityCostFunction::FtBurn => C::cost_ft_burn(n),
            ClarityCostFunction::NftMint => C::cost_nft_mint(n),
            ClarityCostFunction::NftTransfer => C::cost_nft_transfer(n),
            ClarityCostFunction::NftOwner => C::cost_nft_owner(n),
            ClarityCostFunction::NftBurn => C::cost_nft_burn(n),
            ClarityCostFunction::PoisonMicroblock => C::poison_microblock(n),
            ClarityCostFunction::BuffToIntLe => C::cost_buff_to_int_le(n),
            ClarityCostFunction::BuffToUIntLe => C::cost_buff_to_uint_le(n),
            ClarityCostFunction::BuffToIntBe => C::cost_buff_to_int_be(n),
            ClarityCostFunction::BuffToUIntBe => C::cost_buff_to_uint_be(n),
            ClarityCostFunction::IsStandard => C::cost_is_standard(n),
            ClarityCostFunction::PrincipalDestruct => C::cost_principal_destruct(n),
            ClarityCostFunction::PrincipalConstruct => C::cost_principal_construct(n),
            ClarityCostFunction::StringToInt => C::cost_string_to_int(n),
            ClarityCostFunction::StringToUInt => C::cost_string_to_uint(n),
            ClarityCostFunction::IntToAscii => C::cost_int_to_ascii(n),
            ClarityCostFunction::IntToUtf8 => C::cost_int_to_utf8(n),
            ClarityCostFunction::GetBurnBlockInfo => C::cost_burn_block_info(n),
            ClarityCostFunction::StxGetAccount => C::cost_stx_account(n),
            ClarityCostFunction::Slice => C::cost_slice(n),
            ClarityCostFunction::ToConsensusBuff => C::cost_to_consensus_buff(n),
            ClarityCostFunction::FromConsensusBuff => C::cost_from_consensus_buff(n),
            ClarityCostFunction::StxTransferMemo => C::cost_stx_transfer_memo(n),
            ClarityCostFunction::ReplaceAt => C::cost_replace_at(n),
            ClarityCostFunction::AsContract => C::cost_as_contract(n),
            ClarityCostFunction::BitwiseAnd => C::cost_bitwise_and(n),
            ClarityCostFunction::BitwiseOr => C::cost_bitwise_or(n),
            ClarityCostFunction::BitwiseNot => C::cost_bitwise_not(n),
            ClarityCostFunction::BitwiseLShift => C::cost_bitwise_left_shift(n),
            ClarityCostFunction::BitwiseRShift => C::cost_bitwise_right_shift(n),
            ClarityCostFunction::Unimplemented => Err(RuntimeErrorType::NotImplemented.into()),
        }
    }
}
