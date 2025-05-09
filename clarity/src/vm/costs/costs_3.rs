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

/// This file implements the cost functions from costs-3.clar in Rust.
use super::cost_functions::{linear, logn, nlogn, CostValues};
use super::ExecutionCost;
use crate::vm::errors::InterpreterResult;

pub struct Costs3;

impl CostValues for Costs3 {
    fn cost_analysis_type_annotate(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 9)))
    }

    fn cost_analysis_type_check(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 113, 1)))
    }

    fn cost_analysis_type_lookup(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 4)))
    }

    fn cost_analysis_visit(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(1))
    }

    fn cost_analysis_iterable_func(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 14)))
    }

    fn cost_analysis_option_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(5))
    }

    fn cost_analysis_option_check(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(4))
    }

    fn cost_analysis_bind_name(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 59)))
    }

    fn cost_analysis_list_items_check(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 4)))
    }

    fn cost_analysis_check_tuple_get(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(logn(n, 1, 2)?))
    }

    fn cost_analysis_check_tuple_merge(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 45, 49)?))
    }

    fn cost_analysis_check_tuple_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 3, 5)?))
    }

    fn cost_analysis_tuple_items_check(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 28)))
    }

    fn cost_analysis_check_let(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 10)))
    }

    fn cost_analysis_lookup_function(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(18))
    }

    fn cost_analysis_lookup_function_types(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 26)))
    }

    fn cost_analysis_lookup_variable_const(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(15))
    }

    fn cost_analysis_lookup_variable_depth(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 1, 12)?))
    }

    fn cost_ast_parse(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 27, 81)))
    }

    fn cost_ast_cycle_detection(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 141, 72)))
    }

    fn cost_analysis_storage(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 2, 94),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_analysis_use_trait_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 698),
            write_length: linear(n, 1, 1),
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_analysis_fetch_contract_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 1516),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_analysis_get_function_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 78, 1307),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_lookup_variable_depth(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 1)))
    }

    fn cost_lookup_variable_size(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 1)))
    }

    fn cost_lookup_function(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(16))
    }

    fn cost_bind_name(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(216))
    }

    fn cost_inner_type_check_cost(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 2, 5)))
    }

    fn cost_user_function_application(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 26, 5)))
    }

    fn cost_let(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 117, 178)))
    }

    fn cost_if(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(168))
    }

    fn cost_asserts(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(128))
    }

    fn cost_map(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1198, 3067)))
    }

    fn cost_filter(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(407))
    }

    fn cost_len(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(429))
    }

    fn cost_element_at(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(498))
    }

    fn cost_index_of(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 211)))
    }

    fn cost_fold(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(460))
    }

    fn cost_list_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 14, 164)))
    }

    fn cost_type_parse_step(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(4))
    }

    fn cost_tuple_get(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 4, 1736)?))
    }

    fn cost_tuple_merge(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 4, 408)))
    }

    fn cost_tuple_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 10, 1876)?))
    }

    fn cost_add(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 11, 125)))
    }

    fn cost_sub(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 11, 125)))
    }

    fn cost_mul(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 13, 125)))
    }

    fn cost_div(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 13, 125)))
    }

    fn cost_geq(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 7, 128)))
    }

    fn cost_leq(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 7, 128)))
    }

    fn cost_le(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 7, 128)))
    }

    fn cost_ge(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 7, 128)))
    }

    fn cost_int_cast(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(135))
    }

    fn cost_mod(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(141))
    }

    fn cost_pow(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(143))
    }

    fn cost_sqrti(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(142))
    }

    fn cost_log2(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(133))
    }

    fn cost_xor(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 15, 129)))
    }

    fn cost_not(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(138))
    }

    fn cost_eq(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 7, 151)))
    }

    fn cost_begin(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(151))
    }

    fn cost_hash160(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 188)))
    }

    fn cost_sha256(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 100)))
    }

    fn cost_sha512(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 176)))
    }

    fn cost_sha512t256(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 56)))
    }

    fn cost_keccak256(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 127)))
    }

    fn cost_secp256k1recover(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(8655))
    }

    fn cost_secp256k1verify(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(8349))
    }

    fn cost_print(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 15, 1458)))
    }

    fn cost_some_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(199))
    }

    fn cost_ok_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(199))
    }

    fn cost_err_cons(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(199))
    }

    fn cost_default_to(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(268))
    }

    fn cost_unwrap_ret(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(274))
    }

    fn cost_unwrap_err_or_ret(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(302))
    }

    fn cost_is_okay(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(258))
    }

    fn cost_is_none(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(214))
    }

    fn cost_is_err(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(245))
    }

    fn cost_is_some(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(195))
    }

    fn cost_unwrap(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(252))
    }

    fn cost_unwrap_err(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(248))
    }

    fn cost_try_ret(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(240))
    }

    fn cost_match(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(264))
    }

    fn cost_or(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 3, 120)))
    }

    fn cost_and(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 3, 120)))
    }

    fn cost_append(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 73, 285)))
    }

    fn cost_concat(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 37, 220)))
    }

    fn cost_as_max_len(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(475))
    }

    fn cost_contract_call(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(134))
    }

    fn cost_contract_of(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(13400))
    }

    fn cost_principal_of(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(984))
    }

    fn cost_at_block(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 1327,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_load_contract(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 80),
            write_length: 0,
            write_count: 0,
            // set to 3 because of the associated metadata loads
            read_count: 3,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_create_map(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 1564),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_create_var(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 7, 2025),
            write_length: linear(n, 1, 1),
            write_count: 2,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_create_nft(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 1570),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_create_ft(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 1831,
            write_length: 1,
            write_count: 2,
            read_count: 0,
            read_length: 0,
        })
    }

    fn cost_fetch_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 1025),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_set_entry(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 4, 1899),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 0,
        })
    }

    fn cost_fetch_var(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 1, 468),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    fn cost_set_var(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 5, 655),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 0,
        })
    }

    fn cost_contract_storage(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 11, 7165),
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
            runtime: 4294,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_stx_transfer(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 4640,
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_ft_mint(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 1479,
            write_length: 1,
            write_count: 2,
            read_count: 2,
            read_length: 1,
        })
    }

    fn cost_ft_transfer(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 549,
            write_length: 1,
            write_count: 2,
            read_count: 2,
            read_length: 1,
        })
    }

    fn cost_ft_balance(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 479,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_nft_mint(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 575),
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_nft_transfer(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 572),
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
            runtime: 420,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_ft_burn(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 549,
            write_length: 1,
            write_count: 2,
            read_count: 2,
            read_length: 1,
        })
    }

    fn cost_nft_burn(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: linear(n, 9, 572),
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn poison_microblock(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 17485,
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_buff_to_int_le(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(141))
    }

    fn cost_buff_to_uint_le(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(141))
    }

    fn cost_buff_to_int_be(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(141))
    }

    fn cost_buff_to_uint_be(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(141))
    }

    fn cost_is_standard(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(127))
    }

    fn cost_principal_destruct(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(314))
    }

    fn cost_principal_construct(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(398))
    }

    fn cost_string_to_int(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(168))
    }

    fn cost_string_to_uint(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(168))
    }

    fn cost_int_to_ascii(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(147))
    }

    fn cost_int_to_utf8(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(181))
    }

    fn cost_burn_block_info(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 96479,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_stx_account(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 4654,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_slice(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(448))
    }

    fn cost_to_consensus_buff(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 233)))
    }

    fn cost_from_consensus_buff(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(nlogn(n, 3, 185)?))
    }

    fn cost_stx_transfer_memo(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost {
            runtime: 4709,
            write_length: 1,
            write_count: 1,
            read_count: 1,
            read_length: 1,
        })
    }

    fn cost_replace_at(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 1, 561)))
    }

    fn cost_as_contract(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(138))
    }

    fn cost_bitwise_and(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 15, 129)))
    }

    fn cost_bitwise_or(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(linear(n, 15, 129)))
    }

    fn cost_bitwise_not(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(147))
    }

    fn cost_bitwise_left_shift(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(167))
    }

    fn cost_bitwise_right_shift(n: u64) -> InterpreterResult<ExecutionCost> {
        Ok(ExecutionCost::runtime(167))
    }
}
