// Copyright (C) 2025 Stacks Open Internet Foundation
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

/// This file implements the cost functions from costs-2-testnet.clar in Rust.
use super::cost_functions::{linear, logn, nlogn, CostValues};
use super::ExecutionCost;
use crate::vm::errors::{InterpreterResult, RuntimeErrorType};

pub struct Costs2Testnet;

impl CostValues for Costs2Testnet {
    fn cost_analysis_type_annotate(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 9)))
    }

    fn cost_analysis_type_check(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 113, 1)))
    }

    fn cost_analysis_type_lookup(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 6)))
    }

    fn cost_analysis_visit(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(1))
    }

    fn cost_analysis_iterable_func(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 14)))
    }

    fn cost_analysis_option_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(6))
    }

    fn cost_analysis_option_check(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(3))
    }

    fn cost_analysis_bind_name(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 176)))
    }

    fn cost_analysis_list_items_check(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 4)))
    }

    fn cost_analysis_check_tuple_get(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(logn(n, 1, 2)?))
    }

    fn cost_analysis_check_tuple_merge(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1000, 1000)))
    }

    fn cost_analysis_check_tuple_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 3, 5)?))
    }

    fn cost_analysis_tuple_items_check(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 59)))
    }

    fn cost_analysis_check_let(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 12)))
    }

    fn cost_analysis_lookup_function(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(20))
    }

    fn cost_analysis_lookup_function_types(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 28)))
    }

    fn cost_analysis_lookup_variable_const(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(15))
    }

    fn cost_analysis_lookup_variable_depth(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 1, 34)?))
    }

    fn cost_ast_parse(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 172, 287441)))
    }

    fn cost_ast_cycle_detection(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 141, 72)))
    }

    fn cost_analysis_storage(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 2, 100),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_analysis_use_trait_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 723),
            write_length: linear(n, 1, 1),
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_analysis_get_function_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 81, 1303),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_analysis_fetch_contract_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1000, 1000),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_lookup_variable_depth(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 14)))
    }

    fn cost_lookup_variable_size(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 1)))
    }

    fn cost_lookup_function(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(16))
    }

    fn cost_bind_name(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(256))
    }

    fn cost_inner_type_check_cost(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 9)))
    }

    fn cost_user_function_application(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 26, 140)))
    }

    fn cost_let(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 146, 862)))
    }

    fn cost_if(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(200))
    }

    fn cost_asserts(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(158))
    }

    fn cost_map(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1210, 3314)))
    }

    fn cost_filter(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(460))
    }

    fn cost_len(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(486))
    }

    fn cost_element_at(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(619))
    }

    fn cost_index_of(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 243)))
    }

    fn cost_fold(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(483))
    }

    fn cost_list_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 14, 198)))
    }

    fn cost_type_parse_step(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(5))
    }

    fn cost_tuple_get(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 4, 1780)?))
    }

    fn cost_tuple_merge(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 4, 646)))
    }

    fn cost_tuple_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 11, 1101)?))
    }

    fn cost_add(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 12, 156)))
    }

    fn cost_sub(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 12, 156)))
    }

    fn cost_mul(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 14, 157)))
    }

    fn cost_div(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 14, 157)))
    }

    fn cost_geq(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(166))
    }

    fn cost_leq(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(166))
    }

    fn cost_le(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(166))
    }

    fn cost_ge(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(166))
    }

    fn cost_int_cast(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(164))
    }

    fn cost_mod(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(168))
    }

    fn cost_pow(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(170))
    }

    fn cost_sqrti(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(167))
    }

    fn cost_log2(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(161))
    }

    fn cost_xor(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(167))
    }

    fn cost_not(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(162))
    }

    fn cost_eq(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 7, 172)))
    }

    fn cost_begin(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(202))
    }

    fn cost_hash160(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 201)))
    }

    fn cost_sha256(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 100)))
    }

    fn cost_sha512(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 176)))
    }

    fn cost_sha512t256(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 188)))
    }

    fn cost_keccak256(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 221)))
    }

    fn cost_secp256k1recover(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(14344))
    }

    fn cost_secp256k1verify(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(13540))
    }

    fn cost_print(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 3, 1413)))
    }

    fn cost_some_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(230))
    }

    fn cost_ok_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(230))
    }

    fn cost_err_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(230))
    }

    fn cost_default_to(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(249))
    }

    fn cost_unwrap_ret(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(299))
    }

    fn cost_unwrap_err_or_ret(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(339))
    }

    fn cost_is_okay(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(287))
    }

    fn cost_is_none(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(287))
    }

    fn cost_is_err(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(287))
    }

    fn cost_is_some(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(287))
    }

    fn cost_unwrap(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(284))
    }

    fn cost_unwrap_err(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(264))
    }

    fn cost_try_ret(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(256))
    }

    fn cost_match(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(286))
    }

    fn cost_or(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 3, 149)))
    }

    fn cost_and(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 3, 149)))
    }

    fn cost_append(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 71, 176)))
    }

    fn cost_concat(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 75, 244)))
    }

    fn cost_as_max_len(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(475))
    }

    fn cost_contract_call(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(153))
    }

    fn cost_contract_of(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(13400))
    }

    fn cost_principal_of(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(39))
    }

    fn cost_at_block(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 210,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_load_contract(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 157),
            write_length: 0,
            write_count: 0,
            // set to 3 because of the associated metadata loads
            read_count: 3,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_create_map(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 1631),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_create_var(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 7, 2152),
            write_length: linear(n, 1, 1),
            write_count: 2,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_create_nft(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 1610),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_create_ft(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 1972,
            write_length: 1,
            write_count: 2,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_fetch_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 1539),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_set_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 4, 2204),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 0,
        })
    }

    fn cost_fetch_var(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 543),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_set_var(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 5, 691),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 0,
        })
    }

    fn cost_contract_storage(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 13, 7982),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_block_info(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 6321,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_stx_balance(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 1385,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_stx_transfer(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 1430,
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_ft_mint(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 1645,
            write_length: 1,
            write_count: 2,
            read_count: 2,
            read_length: 1,
        })
    }

    fn cost_ft_transfer(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 612,
            write_length: 1,
            write_count: 2,
            read_count: 2,
            read_length: 1,
        })
    }

    fn cost_ft_balance(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 547,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_nft_mint(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 795),
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_nft_transfer(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 795),
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_nft_owner(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 795),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_ft_get_supply(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 483,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_ft_burn(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 612,
            write_length: 1,
            write_count: 2,
            read_count: 2,
            read_length: 1,
        })
    }

    fn cost_nft_burn(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 795),
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn poison_microblock(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 29568,
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_buff_to_int_le(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_buff_to_uint_le(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_buff_to_int_be(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_buff_to_uint_be(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_is_standard(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_principal_destruct(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_principal_construct(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_string_to_int(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_string_to_uint(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_int_to_ascii(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_int_to_utf8(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_burn_block_info(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_stx_account(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_slice(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_to_consensus_buff(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_from_consensus_buff(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_stx_transfer_memo(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_replace_at(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_as_contract(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_bitwise_and(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_bitwise_or(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_bitwise_not(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_bitwise_left_shift(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }

    fn cost_bitwise_right_shift(n: u64) -> InterpreterResult<ExecutionCost> {
        Err(RuntimeErrorType::NotImplemented.into())
    }
}
