// Copyright (C) 2026 Stacks Open Internet Foundation
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
/// This file implements the cost functions from costs-5.clar in Rust.
/// Costs5 forwards to Costs4 for every existing cost function and provides
/// concrete values for the cost functions newly introduced in Clarity 6
/// (`cost_verify_merkle_proof` and `cost_get_bitcoin_tx_output`), which
/// `Costs4` returns `NotImplemented` for.
use super::cost_functions::{CostValues, linear};
use super::costs_4::Costs4;
use crate::vm::errors::VmExecutionError;

pub struct Costs5;

impl CostValues for Costs5 {
    // Forward all costs to Costs4 to avoid duplication.
    fn cost_analysis_type_annotate(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_type_annotate(n)
    }
    fn cost_analysis_type_check(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_type_check(n)
    }
    fn cost_analysis_type_lookup(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_type_lookup(n)
    }
    fn cost_analysis_visit(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_visit(n)
    }
    fn cost_analysis_iterable_func(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_iterable_func(n)
    }
    fn cost_analysis_option_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_option_cons(n)
    }
    fn cost_analysis_option_check(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_option_check(n)
    }
    fn cost_analysis_bind_name(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_bind_name(n)
    }
    fn cost_analysis_list_items_check(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_list_items_check(n)
    }
    fn cost_analysis_check_tuple_get(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_check_tuple_get(n)
    }
    fn cost_analysis_check_tuple_merge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_check_tuple_merge(n)
    }
    fn cost_analysis_check_tuple_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_check_tuple_cons(n)
    }
    fn cost_analysis_tuple_items_check(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_tuple_items_check(n)
    }
    fn cost_analysis_check_let(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_check_let(n)
    }
    fn cost_analysis_lookup_function(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_lookup_function(n)
    }
    fn cost_analysis_lookup_function_types(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_lookup_function_types(n)
    }
    fn cost_analysis_lookup_variable_const(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_lookup_variable_const(n)
    }
    fn cost_analysis_lookup_variable_depth(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_lookup_variable_depth(n)
    }
    fn cost_ast_parse(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ast_parse(n)
    }
    fn cost_ast_cycle_detection(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ast_cycle_detection(n)
    }
    fn cost_analysis_storage(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_storage(n)
    }
    fn cost_analysis_use_trait_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_use_trait_entry(n)
    }
    fn cost_analysis_get_function_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_get_function_entry(n)
    }
    fn cost_analysis_fetch_contract_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_analysis_fetch_contract_entry(n)
    }
    fn cost_lookup_variable_depth(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_lookup_variable_depth(n)
    }
    fn cost_lookup_variable_size(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_lookup_variable_size(n)
    }
    fn cost_lookup_function(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_lookup_function(n)
    }
    fn cost_bind_name(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_bind_name(n)
    }
    fn cost_inner_type_check_cost(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_inner_type_check_cost(n)
    }
    fn cost_user_function_application(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_user_function_application(n)
    }
    fn cost_let(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_let(n)
    }
    fn cost_if(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_if(n)
    }
    fn cost_asserts(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_asserts(n)
    }
    fn cost_map(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_map(n)
    }
    fn cost_filter(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_filter(n)
    }
    fn cost_len(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_len(n)
    }
    fn cost_element_at(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_element_at(n)
    }
    fn cost_index_of(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_index_of(n)
    }
    fn cost_fold(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_fold(n)
    }
    fn cost_list_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_list_cons(n)
    }
    fn cost_type_parse_step(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_type_parse_step(n)
    }
    fn cost_tuple_get(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_tuple_get(n)
    }
    fn cost_tuple_merge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_tuple_merge(n)
    }
    fn cost_tuple_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_tuple_cons(n)
    }
    fn cost_add(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_add(n)
    }
    fn cost_sub(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_sub(n)
    }
    fn cost_mul(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_mul(n)
    }
    fn cost_div(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_div(n)
    }
    fn cost_geq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_geq(n)
    }
    fn cost_leq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_leq(n)
    }
    fn cost_le(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_le(n)
    }
    fn cost_ge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ge(n)
    }
    fn cost_int_cast(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_int_cast(n)
    }
    fn cost_mod(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_mod(n)
    }
    fn cost_pow(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_pow(n)
    }
    fn cost_sqrti(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_sqrti(n)
    }
    fn cost_log2(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_log2(n)
    }
    fn cost_xor(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_xor(n)
    }
    fn cost_not(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_not(n)
    }
    fn cost_eq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_eq(n)
    }
    fn cost_begin(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_begin(n)
    }
    fn cost_hash160(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_hash160(n)
    }
    fn cost_sha256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_sha256(n)
    }
    fn cost_sha512(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_sha512(n)
    }
    fn cost_sha512t256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_sha512t256(n)
    }
    fn cost_keccak256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_keccak256(n)
    }
    fn cost_secp256k1recover(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_secp256k1recover(n)
    }
    fn cost_secp256k1verify(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_secp256k1verify(n)
    }
    fn cost_print(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_print(n)
    }
    fn cost_some_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_some_cons(n)
    }
    fn cost_ok_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ok_cons(n)
    }
    fn cost_err_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_err_cons(n)
    }
    fn cost_default_to(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_default_to(n)
    }
    fn cost_unwrap_ret(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_unwrap_ret(n)
    }
    fn cost_unwrap_err_or_ret(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_unwrap_err_or_ret(n)
    }
    fn cost_is_okay(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_is_okay(n)
    }
    fn cost_is_none(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_is_none(n)
    }
    fn cost_is_err(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_is_err(n)
    }
    fn cost_is_some(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_is_some(n)
    }
    fn cost_unwrap(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_unwrap(n)
    }
    fn cost_unwrap_err(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_unwrap_err(n)
    }
    fn cost_try_ret(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_try_ret(n)
    }
    fn cost_match(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_match(n)
    }
    fn cost_or(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_or(n)
    }
    fn cost_and(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_and(n)
    }
    fn cost_append(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_append(n)
    }
    fn cost_concat(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_concat(n)
    }
    fn cost_as_max_len(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_as_max_len(n)
    }
    fn cost_contract_call(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_contract_call(n)
    }
    fn cost_contract_of(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_contract_of(n)
    }
    fn cost_principal_of(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_principal_of(n)
    }
    fn cost_at_block(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_at_block(n)
    }
    fn cost_load_contract(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_load_contract(n)
    }
    fn cost_create_map(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_create_map(n)
    }
    fn cost_create_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_create_var(n)
    }
    fn cost_create_nft(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_create_nft(n)
    }
    fn cost_create_ft(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_create_ft(n)
    }
    fn cost_fetch_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_fetch_entry(n)
    }
    fn cost_set_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_set_entry(n)
    }
    fn cost_fetch_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_fetch_var(n)
    }
    fn cost_set_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_set_var(n)
    }
    fn cost_contract_storage(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_contract_storage(n)
    }
    fn cost_block_info(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_block_info(n)
    }
    fn cost_stx_balance(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_stx_balance(n)
    }
    fn cost_stx_transfer(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_stx_transfer(n)
    }
    fn cost_ft_mint(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ft_mint(n)
    }
    fn cost_ft_transfer(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ft_transfer(n)
    }
    fn cost_ft_balance(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ft_balance(n)
    }
    fn cost_ft_get_supply(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ft_get_supply(n)
    }
    fn cost_ft_burn(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_ft_burn(n)
    }
    fn cost_nft_mint(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_nft_mint(n)
    }
    fn cost_nft_transfer(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_nft_transfer(n)
    }
    fn cost_nft_owner(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_nft_owner(n)
    }
    fn cost_nft_burn(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_nft_burn(n)
    }
    fn poison_microblock(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::poison_microblock(n)
    }
    fn cost_buff_to_int_le(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_buff_to_int_le(n)
    }
    fn cost_buff_to_uint_le(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_buff_to_uint_le(n)
    }
    fn cost_buff_to_int_be(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_buff_to_int_be(n)
    }
    fn cost_buff_to_uint_be(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_buff_to_uint_be(n)
    }
    fn cost_is_standard(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_is_standard(n)
    }
    fn cost_principal_destruct(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_principal_destruct(n)
    }
    fn cost_principal_construct(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_principal_construct(n)
    }
    fn cost_string_to_int(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_string_to_int(n)
    }
    fn cost_string_to_uint(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_string_to_uint(n)
    }
    fn cost_int_to_ascii(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_int_to_ascii(n)
    }
    fn cost_int_to_utf8(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_int_to_utf8(n)
    }
    fn cost_burn_block_info(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_burn_block_info(n)
    }
    fn cost_stx_account(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_stx_account(n)
    }
    fn cost_slice(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_slice(n)
    }
    fn cost_to_consensus_buff(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_to_consensus_buff(n)
    }
    fn cost_from_consensus_buff(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_from_consensus_buff(n)
    }
    fn cost_stx_transfer_memo(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_stx_transfer_memo(n)
    }
    fn cost_replace_at(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_replace_at(n)
    }
    fn cost_as_contract(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_as_contract(n)
    }
    fn cost_bitwise_and(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_bitwise_and(n)
    }
    fn cost_bitwise_or(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_bitwise_or(n)
    }
    fn cost_bitwise_not(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_bitwise_not(n)
    }
    fn cost_bitwise_left_shift(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_bitwise_left_shift(n)
    }
    fn cost_bitwise_right_shift(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_bitwise_right_shift(n)
    }
    fn cost_contract_hash(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_contract_hash(n)
    }
    fn cost_to_ascii(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_to_ascii(n)
    }
    fn cost_restrict_assets(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_restrict_assets(n)
    }
    fn cost_as_contract_safe(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_as_contract_safe(n)
    }
    fn cost_secp256r1verify(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_secp256r1verify(n)
    }

    // New cost functions in Clarity 6.

    /// Per-sibling cost of merkle proof verification: each level is one
    /// double-SHA-256 over a 64-byte buffer plus loop bookkeeping.
    /// FIXME: Placeholder values pending benchmarking.
    fn cost_verify_merkle_proof(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n, 125, 502)))
    }

    /// Cost of parsing a Bitcoin tx and extracting one output, plus computing
    /// the canonical txid (one double-SHA-256 over the non-witness
    /// serialization). Linear in the byte length of `tx-bytes`.
    fn cost_get_bitcoin_tx_output(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 10, 125, 291)))
    }

    fn cost_ed25519verify(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 10, 125, 7880)))
    }

    fn cost_secp256k1decompress(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(1035))
    }
}
