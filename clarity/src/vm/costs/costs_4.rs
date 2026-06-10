// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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
/// This file implements the cost functions from costs-4.clar in Rust.
/// For Clarity 4, all cost functions are the same as in costs-3, except
/// for the new `cost_contract_hash` function. To avoid duplication, this
/// implementation forwards to `Costs3` for all existing functions and
/// overrides only `cost_contract_hash`.
use super::cost_functions::CostValues;
use super::costs_3::Costs3;
use crate::vm::costs::cost_functions::linear;
use crate::vm::errors::VmExecutionError;

pub struct Costs4;

impl CostValues for Costs4 {
    // Forward all costs to Costs3 to avoid duplication.
    fn cost_analysis_type_annotate(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_type_annotate(n)
    }
    fn cost_analysis_type_check(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_type_check(n)
    }
    fn cost_analysis_type_lookup(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_type_lookup(n)
    }
    fn cost_analysis_visit(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_visit(n)
    }
    fn cost_analysis_iterable_func(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_iterable_func(n)
    }
    fn cost_analysis_option_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_option_cons(n)
    }
    fn cost_analysis_option_check(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_option_check(n)
    }
    fn cost_analysis_bind_name(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_bind_name(n)
    }
    fn cost_analysis_list_items_check(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_list_items_check(n)
    }
    fn cost_analysis_check_tuple_get(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_check_tuple_get(n)
    }
    fn cost_analysis_check_tuple_merge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_check_tuple_merge(n)
    }
    fn cost_analysis_check_tuple_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_check_tuple_cons(n)
    }
    fn cost_analysis_tuple_items_check(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_tuple_items_check(n)
    }
    fn cost_analysis_check_let(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_check_let(n)
    }
    fn cost_analysis_lookup_function(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_lookup_function(n)
    }
    fn cost_analysis_lookup_function_types(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_lookup_function_types(n)
    }
    fn cost_analysis_lookup_variable_const(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_lookup_variable_const(n)
    }
    fn cost_analysis_lookup_variable_depth(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_lookup_variable_depth(n)
    }
    fn cost_ast_parse(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ast_parse(n)
    }
    fn cost_ast_cycle_detection(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ast_cycle_detection(n)
    }
    fn cost_analysis_storage(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_storage(n)
    }
    fn cost_analysis_use_trait_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_use_trait_entry(n)
    }
    fn cost_analysis_get_function_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_get_function_entry(n)
    }
    fn cost_analysis_fetch_contract_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_analysis_fetch_contract_entry(n)
    }
    fn cost_lookup_variable_depth(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_lookup_variable_depth(n)
    }
    fn cost_lookup_variable_size(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_lookup_variable_size(n)
    }
    fn cost_lookup_function(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_lookup_function(n)
    }
    fn cost_bind_name(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_bind_name(n)
    }
    fn cost_inner_type_check_cost(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_inner_type_check_cost(n)
    }
    fn cost_user_function_application(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_user_function_application(n)
    }
    fn cost_let(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_let(n)
    }
    fn cost_if(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_if(n)
    }
    fn cost_asserts(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_asserts(n)
    }
    fn cost_map(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_map(n)
    }
    fn cost_filter(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_filter(n)
    }
    fn cost_len(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_len(n)
    }
    fn cost_element_at(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_element_at(n)
    }
    fn cost_index_of(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_index_of(n)
    }
    fn cost_fold(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_fold(n)
    }
    fn cost_list_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_list_cons(n)
    }
    fn cost_type_parse_step(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_type_parse_step(n)
    }
    fn cost_tuple_get(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_tuple_get(n)
    }
    fn cost_tuple_merge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_tuple_merge(n)
    }
    fn cost_tuple_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_tuple_cons(n)
    }
    fn cost_add(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_add(n)
    }
    fn cost_sub(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_sub(n)
    }
    fn cost_mul(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_mul(n)
    }
    fn cost_div(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_div(n)
    }
    fn cost_geq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_geq(n)
    }
    fn cost_leq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_leq(n)
    }
    fn cost_le(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_le(n)
    }
    fn cost_ge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ge(n)
    }
    fn cost_int_cast(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_int_cast(n)
    }
    fn cost_mod(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_mod(n)
    }
    fn cost_pow(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_pow(n)
    }
    fn cost_sqrti(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_sqrti(n)
    }
    fn cost_log2(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_log2(n)
    }
    fn cost_xor(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_xor(n)
    }
    fn cost_not(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_not(n)
    }
    fn cost_eq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_eq(n)
    }
    fn cost_begin(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_begin(n)
    }
    fn cost_hash160(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_hash160(n)
    }
    fn cost_sha256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_sha256(n)
    }
    fn cost_sha512(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_sha512(n)
    }
    fn cost_sha512t256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_sha512t256(n)
    }
    fn cost_keccak256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_keccak256(n)
    }
    fn cost_secp256k1recover(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_secp256k1recover(n)
    }
    fn cost_secp256k1verify(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_secp256k1verify(n)
    }
    fn cost_print(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_print(n)
    }
    fn cost_some_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_some_cons(n)
    }
    fn cost_ok_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ok_cons(n)
    }
    fn cost_err_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_err_cons(n)
    }
    fn cost_default_to(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_default_to(n)
    }
    fn cost_unwrap_ret(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_unwrap_ret(n)
    }
    fn cost_unwrap_err_or_ret(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_unwrap_err_or_ret(n)
    }
    fn cost_is_okay(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_is_okay(n)
    }
    fn cost_is_none(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_is_none(n)
    }
    fn cost_is_err(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_is_err(n)
    }
    fn cost_is_some(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_is_some(n)
    }
    fn cost_unwrap(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_unwrap(n)
    }
    fn cost_unwrap_err(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_unwrap_err(n)
    }
    fn cost_try_ret(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_try_ret(n)
    }
    fn cost_match(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_match(n)
    }
    fn cost_or(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_or(n)
    }
    fn cost_and(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_and(n)
    }
    fn cost_append(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_append(n)
    }
    fn cost_concat(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_concat(n)
    }
    fn cost_as_max_len(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_as_max_len(n)
    }
    fn cost_contract_call(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_contract_call(n)
    }
    fn cost_contract_of(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_contract_of(n)
    }
    fn cost_principal_of(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_principal_of(n)
    }
    fn cost_at_block(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_at_block(n)
    }
    fn cost_load_contract(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_load_contract(n)
    }
    fn cost_create_map(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_create_map(n)
    }
    fn cost_create_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_create_var(n)
    }
    fn cost_create_nft(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_create_nft(n)
    }
    fn cost_create_ft(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_create_ft(n)
    }
    fn cost_fetch_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_fetch_entry(n)
    }
    fn cost_set_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_set_entry(n)
    }
    fn cost_fetch_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_fetch_var(n)
    }
    fn cost_set_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_set_var(n)
    }
    fn cost_contract_storage(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_contract_storage(n)
    }
    fn cost_block_info(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_block_info(n)
    }
    fn cost_stx_balance(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_stx_balance(n)
    }
    fn cost_stx_transfer(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_stx_transfer(n)
    }
    fn cost_ft_mint(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ft_mint(n)
    }
    fn cost_ft_transfer(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ft_transfer(n)
    }
    fn cost_ft_balance(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ft_balance(n)
    }
    fn cost_ft_get_supply(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ft_get_supply(n)
    }
    fn cost_ft_burn(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_ft_burn(n)
    }
    fn cost_nft_mint(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_nft_mint(n)
    }
    fn cost_nft_transfer(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_nft_transfer(n)
    }
    fn cost_nft_owner(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_nft_owner(n)
    }
    fn cost_nft_burn(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_nft_burn(n)
    }
    fn poison_microblock(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::poison_microblock(n)
    }
    fn cost_buff_to_int_le(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_buff_to_int_le(n)
    }
    fn cost_buff_to_uint_le(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_buff_to_uint_le(n)
    }
    fn cost_buff_to_int_be(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_buff_to_int_be(n)
    }
    fn cost_buff_to_uint_be(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_buff_to_uint_be(n)
    }
    fn cost_is_standard(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_is_standard(n)
    }
    fn cost_principal_destruct(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_principal_destruct(n)
    }
    fn cost_principal_construct(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_principal_construct(n)
    }
    fn cost_string_to_int(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_string_to_int(n)
    }
    fn cost_string_to_uint(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_string_to_uint(n)
    }
    fn cost_int_to_ascii(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_int_to_ascii(n)
    }
    fn cost_int_to_utf8(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_int_to_utf8(n)
    }
    fn cost_burn_block_info(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_burn_block_info(n)
    }
    fn cost_stx_account(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_stx_account(n)
    }
    fn cost_slice(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_slice(n)
    }
    fn cost_to_consensus_buff(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_to_consensus_buff(n)
    }
    fn cost_from_consensus_buff(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_from_consensus_buff(n)
    }
    fn cost_stx_transfer_memo(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_stx_transfer_memo(n)
    }
    fn cost_replace_at(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_replace_at(n)
    }
    fn cost_as_contract(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_as_contract(n)
    }
    fn cost_bitwise_and(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_bitwise_and(n)
    }
    fn cost_bitwise_or(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_bitwise_or(n)
    }
    fn cost_bitwise_not(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_bitwise_not(n)
    }
    fn cost_bitwise_left_shift(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_bitwise_left_shift(n)
    }
    fn cost_bitwise_right_shift(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs3::cost_bitwise_right_shift(n)
    }

    // --- New in costs-4 ---

    fn cost_contract_hash(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: 188,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 32,
        })
    }

    fn cost_to_ascii(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n, 16, 150)))
    }

    fn cost_restrict_assets(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n, 125, 750)))
    }

    fn cost_as_contract_safe(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n, 125, 888)))
    }

    fn cost_secp256r1verify(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(51750))
    }
}
