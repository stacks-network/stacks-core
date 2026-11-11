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
/// Cost functions for Clarity 6 / Epoch 4.0, calibrated via `clarity-cost-bench` under
/// Callgrind on Linux x86_64.  All arithmetic and sequence operations are overridden with
/// bench-derived formulas; analysis-phase, state-dependent, and uncalibrated functions
/// continue to forward to `Costs4`.
///
/// Calibration baseline: **1 cost unit = 80,000 CPU instructions** (fixed round value chosen
/// to place the base overhead of any call at ≈38 units, yielding a clean block-limit budget).
use super::cost_functions::{CostValues, linear};
use super::costs_4::Costs4;
use crate::vm::errors::VmExecutionError;

pub struct Costs5;

impl CostValues for Costs5 {
    // Analysis / compile-time pass — not covered by the runtime bench; forward to Costs4.
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
    // Interpreter overhead — scale with lexical depth / name-size; not covered by bench.
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
    // Bench: let/uint binding_count=[1..32]; 18,289 instrs/binding + 3,018,689 base.
    // linear(n >> 3, 1, 32): 1 unit per 8 bindings + 32. Max error ±2.
    fn cost_let(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 3, 1, 32)))
    }
    // Control flow — not covered by bench; forward to Costs4.
    fn cost_if(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_if(n)
    }
    fn cost_asserts(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_asserts(n)
    }
    // Bench: map/list-optional-uint (worst case); 27,358 instrs/elem.
    // linear(n >> 2, 1, 32): 1 unit per 4 elements + 32.
    fn cost_map(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 32)))
    }
    // Bench: filter/list-optional-uint (worst case); 26,890 instrs/elem. Same formula.
    fn cost_filter(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 32)))
    }
    // Bench: len/* → 31 units constant; n=args.len()=1 always at runtime.
    fn cost_len(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: element-at/* → 31 units constant; n=args.len()=2 always at runtime.
    fn cost_element_at(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: index-of/buffer buffer_bytes=[1..65536]; 175 instrs/seq_byte + 3,027,948 base.
    // Dispatch: NativeFunction205 with cost_input_sized_vararg → n = serialized(seq) + serialized(elem).
    // For a buffer search: n ≈ buffer_bytes + element_size (both serialized with 5-byte overhead each).
    // 175/80000 ≈ 1/457 units/byte; linear(n >> 9, 1, 38): 1 unit per 512 bytes + 38.
    fn cost_index_of(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: fold/list-bool; 9,604 instrs/elem. linear(n >> 3, 1, 32): 1 unit per 8 elems + 32.
    fn cost_fold(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 3, 1, 32)))
    }
    // Bench: list/bool — same slope as + (5,793 instrs/arg). linear(n >> 4, 1, 31).
    fn cost_list_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    fn cost_type_parse_step(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_type_parse_step(n)
    }
    // Bench: get/tuple-uint field_count=[1..32]; 19,555 instrs/field + 3,027,264 base.
    // linear(n >> 2, 1, 32): 1 unit per 4 fields + 32. Max error ±2.
    fn cost_tuple_get(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 32)))
    }
    // Bench: merge/tuple total_field_count=[1..32]; same slope as get.
    // linear(n >> 2, 1, 32): 1 unit per 4 fields + 32. Max error ±2.
    fn cost_tuple_merge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 32)))
    }
    // Bench: tuple/tuple-bool field_count=[1..32]; 20,524 instrs/field + 3,009,601 base.
    // linear(n >> 2, 1, 31): 1 unit per 4 fields + 31. Max error ±1.
    fn cost_tuple_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 31)))
    }
    // Bench: +/uint arg_count=[1..128]; 5,793 instrs/arg + 3,012,293 base.
    // linear(n >> 4, 1, 31): 1 unit per 16 args + 31. Max error ±1.
    fn cost_add(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    // Bench: -/uint arg_count=[1..128]; 3,187 instrs/arg + 3,078,064 base.
    // linear(n >> 5, 1, 32): 1 unit per 32 args + 32. Max error ±1.
    fn cost_sub(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 5, 1, 32)))
    }
    // Bench: */uint; same slope as + (5,800 instrs/arg). linear(n >> 4, 1, 31).
    fn cost_mul(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    // Bench: //uint; same slope as - (3,187 instrs/arg). linear(n >> 5, 1, 32).
    fn cost_div(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 5, 1, 32)))
    }
    // Bench: >=, <=, <, > / buffer buffer_bytes=[1..65536]; 338 instrs/byte + ~3,015,000 base.
    // Dispatch (Clarity 2): SpecialFunction → n = min(a.size(), b.size()) ≈ buffer_bytes.
    // 338/80000 ≈ 1/237; >> 8 (÷256) closest power-of-2, 8% undercharge.
    // Int (n=16) and string-ascii (n≤128) round to constant 38 via n >> 8 = 0.
    fn cost_geq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 8, 1, 38)))
    }
    fn cost_leq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 8, 1, 38)))
    }
    fn cost_le(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 8, 1, 38)))
    }
    fn cost_ge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 8, 1, 38)))
    }
    // Bench: to-int, mod, pow, sqrti, log2, not all → 31 units constant (n=1 or 2 always).
    fn cost_int_cast(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_mod(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_pow(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_sqrti(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_log2(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: xor/int (n=2 always) → 31 units. bit-xor (n=arg_count) uses same function.
    // linear(n >> 4, 1, 31): at n=2 → 31 ✓; at n=128 → 39 ✓.
    fn cost_xor(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    fn cost_not(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: is-eq/buffer buffer_bytes=[1..65536]; 338 instrs/buffer_byte + 3,016,198 base.
    // Dispatch: NativeFunction205 with cost_input_sized_vararg → n = sum of serialized sizes of all args.
    // For `(is-eq buf_N buf_N)`: n ≈ 2×(buffer_bytes + 5) ≈ 2×buffer_bytes.
    // 338 instrs/buffer_byte = 169 instrs/n_byte; 169/80000 ≈ 1/473; linear(n >> 9, 1, 38).
    fn cost_eq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: begin — same slope as + (5,793 instrs/arg). linear(n >> 4, 1, 31).
    fn cost_begin(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    // Bench: hash160/buffer buffer_bytes=[1..65536]; 213 instrs/byte + 3,028,095 base.
    // Dispatch: NativeFunction205 with cost_input_sized_vararg → n = serialized_size(buffer) ≈ buffer_bytes + 5.
    // Nearest power-of-2 approximation: >> 9 (÷512) slightly undercharges vs exact slope, >> 8 (÷256) overcharges by ~47%.
    fn cost_hash160(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: sha256/buffer buffer_bytes=[1..65536]; 213 instrs/byte + 3,026,373 base. Same formula.
    fn cost_sha256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: sha512/buffer buffer_bytes=[1..65536]; 202 instrs/byte + 3,027,754 base.
    // sha512 is not hardware-accelerated on this bench host; slope slightly lower than sha256.
    fn cost_sha512(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: sha512/256/buffer buffer_bytes=[1..65536]; 202 instrs/byte + 3,029,852 base. Same formula.
    fn cost_sha512t256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: keccak256/buffer buffer_bytes=[1..65536]; 214 instrs/byte + 3,027,832 base. Same formula.
    fn cost_keccak256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: secp256k1-recover? (fixed-size inputs) → 3,047,558 instrs → 38 units.
    // Uses pure-Rust libsecp256k1; n=0 always (SpecialFunction passes 0).
    fn cost_secp256k1recover(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(38))
    }
    // Bench: secp256k1-verify (fixed-size inputs) → 3,047,773 instrs → 38 units.
    // Uses pure-Rust libsecp256k1; n=0 always.
    fn cost_secp256k1verify(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(38))
    }
    // Bench: print/buffer buffer_bytes=[1..1024]; 163 instrs/byte + 3,021,206 base.
    // linear(n >> 9, 1, 31): n=1→31 ✓; n=1029 (1024-byte buf)→33 ✓.
    fn cost_print(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 31)))
    }
    // Bench: some, ok, err, default-to, unwrap!, unwrap-err!, is-ok/none/err/some, try!
    // all → ~3.0M instrs → 31 cost units constant.
    fn cost_some_cons(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_ok_cons(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_err_cons(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_default_to(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_unwrap_ret(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_unwrap_err_or_ret(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_is_okay(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_is_none(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_is_err(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_is_some(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_unwrap(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_unwrap_err(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_try_ret(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: match/* → 31 units constant.
    fn cost_match(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: or/bool arg_count=[1..128]; 5,501 instrs/arg. linear(n >> 4, 1, 31).
    fn cost_or(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    // Bench: and/bool arg_count=[1..128]; 5,793 instrs/arg. linear(n >> 4, 1, 31).
    fn cost_and(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    // Bench: append/list-bool; n = element_type.size() at runtime.
    // bool: n=1 → 31 ✓; optional-uint: n=17 → (17>>4)*1+31=32 ✓.
    fn cost_append(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    // Bench: concat/buffer buffer_bytes=[1..1024]; n = total_bytes of both sequences at runtime.
    // At buffer_bytes=1024: n=2058 → linear(2058>>10, 1, 31) = 33 ✓.
    fn cost_concat(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 10, 1, 31)))
    }
    // Bench: as-max-len?/* → 31 units constant; n=0 at runtime.
    fn cost_as_max_len(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // State-dependent / not calibrated by bench; forward to Costs4.
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
    // Bench: map-get?/buffer → ~44 units constant; n = value byte size.
    fn cost_fetch_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: 44,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }
    // Bench: map-set/buffer; 563 instrs/byte + 4,301,893 base. n=1→45; n=512→47; n=1024→50.
    // linear(n >> 9, 3, 45): 3 units per 512 bytes + 45.
    fn cost_set_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: linear(n >> 9, 3, 45),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 0,
        })
    }
    // Bench: var-get/buffer; 313 instrs/byte + 4,289,144 base. n=1→44; n=512→46; n=1024→48.
    // linear(n >> 9, 2, 44): 2 units per 512 bytes + 44.
    fn cost_fetch_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: linear(n >> 9, 2, 44),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }
    // Bench: var-set/buffer; 839 instrs/byte + 4,329,201 base. n=1→45; n=512→49; n=1024→53.
    // linear(n >> 9, 4, 45): 4 units per 512 bytes + 45.
    fn cost_set_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: linear(n >> 9, 4, 45),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 0,
        })
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
    // Bench: buff-to-int-be/le, buff-to-uint-be/le all → 31 units constant.
    fn cost_buff_to_int_le(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_buff_to_uint_le(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_buff_to_int_be(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_buff_to_uint_be(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: is-standard → 31 units constant.
    fn cost_is_standard(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: principal-destruct?, principal-construct? → 32 units constant.
    fn cost_principal_destruct(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }
    fn cost_principal_construct(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }
    // Bench: string-to-int?/uint? string_chars=[1..20]; ~5,700 instrs/char + 3.0M base.
    // linear(n >> 4, 1, 31): n=1→31 ✓; n=16→32 ✓. n = string_chars (NativeFunction205).
    fn cost_string_to_int(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    fn cost_string_to_uint(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    // Bench: int-to-ascii, int-to-utf8 → 31 units constant.
    fn cost_int_to_ascii(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_int_to_utf8(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_burn_block_info(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_burn_block_info(n)
    }
    fn cost_stx_account(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_stx_account(n)
    }
    // Bench: slice?/buffer buffer_bytes=[1..65536]; 169 instrs/byte + 3,031,376 base.
    // Dispatch: SpecialFunction → n = (right-left) × element_size = number of slice bytes.
    // 169/80000 ≈ 1/473 units/byte; linear(n >> 9, 1, 38): 1 unit per 512 bytes + 38.
    fn cost_slice(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: to-consensus-buff?/buffer buffer_bytes=[1..65536]; 169 instrs/byte + 3,026,478 base.
    // Dispatch: NativeFunction205 with cost_input_sized_vararg → n = serialized_size(value).
    // 169/80000 ≈ 1/473 units/byte; linear(n >> 9, 1, 38): 1 unit per 512 bytes + 38.
    fn cost_to_consensus_buff(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: from-consensus-buff?/buffer buffer_bytes=[1..65536]; 170 instrs/byte + 3,038,449 base.
    // Dispatch: SpecialFunction → n = input_bytes.len() = raw buffer data bytes (not serialized size).
    // 170/80000 ≈ 1/471 units/byte; linear(n >> 9, 1, 38): 1 unit per 512 bytes + 38.
    fn cost_from_consensus_buff(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    fn cost_stx_transfer_memo(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_stx_transfer_memo(n)
    }
    // Bench: replace-at?/buffer buffer_bytes=[1..1024]; 164 instrs/byte + 3,030,435 base.
    // linear(n >> 9, 1, 31): n=1024 → 33 ✓. n = sequence.size() bytes at runtime.
    fn cost_replace_at(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 31)))
    }
    fn cost_as_contract(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_as_contract(n)
    }
    // Bench: bit-and/uint, bit-or/uint arg_count=[1..128]; 5,800 instrs/arg.
    // linear(n >> 4, 1, 31): same formula as +/*.
    fn cost_bitwise_and(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    fn cost_bitwise_or(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    // Bench: bit-not/uint → 31 units constant (single arg).
    fn cost_bitwise_not(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    // Bench: bit-shift-left/right → 31 units constant.
    fn cost_bitwise_left_shift(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_bitwise_right_shift(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_contract_hash(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_contract_hash(n)
    }
    // Bench: to-ascii?/string-utf8 string_chars=[1..1024]; 1,757 instrs/char + 3,022,803 base.
    // linear(n >> 6, 1, 32): 1 unit per 64 chars + 32. Max error ±2.
    fn cost_to_ascii(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 6, 1, 32)))
    }
    fn cost_restrict_assets(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_restrict_assets(n)
    }
    fn cost_as_contract_safe(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_as_contract_safe(n)
    }
    // Bench: secp256r1-verify (fixed-size inputs) → 3,053,177 instrs → 38 units.
    // Uses pure-Rust secp256r1; n=0 always.
    fn cost_secp256r1verify(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(38))
    }
    // Bench: verify-merkle-proof/siblings sibling_count=[1..24]; 14,885 instrs/sibling + 3,057,211 base.
    // n = sibling_count. 14885/80000 ≈ 0.186 units/sibling; linear(n >> 2, 1, 38): 1 unit per 4 siblings + 38.
    fn cost_verify_merkle_proof(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 38)))
    }
    // Bench: get-bitcoin-tx-output?/buffer buffer_bytes=[1..65536]; 186 instrs/byte + 3,026,500 base.
    // Dispatch: NativeFunction205 with cost_input_sized_vararg → n = serialized_size(tx_bytes).
    // 186/80000 ≈ 1/430 units/byte; linear(n >> 9, 1, 38): 1 unit per 512 bytes + 38.
    fn cost_get_bitcoin_tx_output(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 38)))
    }
    // Bench: ed25519-verify/buffer message_bytes=[1..65536]; 169 instrs/msg_byte + 3,095,680 base.
    // Dispatch: NativeFunction205 with cost_input_ed25519_verify → n = message.len() (raw bytes, not serialized).
    // Sig (64 bytes) and pubkey (32 bytes) are fixed-size; their work is absorbed in the higher base.
    // 169/80000 ≈ 1/473 units/msg_byte; base 3,095,680/80,000 = 38.7 → 39; linear(n >> 9, 1, 39).
    fn cost_ed25519verify(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 39)))
    }
    // Bench: secp256k1-decompress? (compressed key, always 33 bytes) → 3,081,532 instrs → 39 units.
    // Uses pure-Rust libsecp256k1; n=1 always (NativeFunction with one argument).
    fn cost_secp256k1decompress(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(39))
    }
}
