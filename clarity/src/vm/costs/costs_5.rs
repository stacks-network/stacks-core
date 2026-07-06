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
/// Calibration baseline: **1 cost unit = 96,528 CPU instructions** (derived from `+/uint`
/// at n=32, where current=33 ≈ bench-suggested=33).
use super::cost_functions::{CostValues, linear};
use super::costs_4::Costs4;
use crate::vm::errors::VmExecutionError;

pub struct Costs5;

impl CostValues for Costs5 {
    // ── Analysis / compile-time pass ─────────────────────────────────────────────────
    // These functions run during contract analysis, not execution.  They are not
    // covered by the runtime bench and continue to forward to Costs4.

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

    // ── Interpreter overhead (variable lookup, binding, type checks) ─────────────────
    // These scale with lexical depth / name-size, not data size; not covered by the
    // runtime bench.  Forward to Costs4.

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
    fn cost_type_parse_step(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_type_parse_step(n)
    }

    // ── Control flow ─────────────────────────────────────────────────────────────────
    // `if` and `asserts!` are not covered by the bench.  Forward to Costs4.

    fn cost_if(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_if(n)
    }
    fn cost_asserts(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_asserts(n)
    }

    // ── Arithmetic: n = arg_count (NativeFunction dispatch → args.len()) ─────────────

    // Bench: +/uint arg_count=[1..128]; fit: 5,793 instrs/arg + 3,012,293 base.
    // n=1: 3,018,086 instrs → 31 units; n=128: 3,753,240 → 39 units.
    // linear(n >> 4, 1, 31): 1 unit per 16 args + 31. Max error ±1.
    fn cost_add(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }

    // Bench: -/uint arg_count=[1..128]; fit: 3,187 instrs/arg + 3,078,064 base.
    // n=1: 3,081,251 → 32; n=128: 3,486,416 → 36.
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

    // ── Comparison / unary / cast: n = 1 or 2 (always small) → constant ─────────────
    // All bench at n=1 give ~3.0M instrs → 31 cost units.

    fn cost_geq(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_leq(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_le(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_ge(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
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
    fn cost_not(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // ── Bitwise ops ───────────────────────────────────────────────────────────────────

    // Bench: bit-and/uint arg_count=[1..128]; 5,800 instrs/arg (same as +).
    // Bench: bit-or/uint; same slope. Both: linear(n >> 4, 1, 31).
    // `xor` (2-arg, n=2) and `bit-xor` (variable, n=arg_count) both use cost_xor.
    // At n=2: (2>>4)*1+31=31 ✓.  At n=128: 8+31=39.
    fn cost_bitwise_and(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    fn cost_bitwise_or(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    fn cost_xor(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }

    // Bench: bit-not/uint n=1 → 3,000,000 instrs → 31 units (single arg, constant).
    fn cost_bitwise_not(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // Bench: bit-shift-left/right both → 31 units constant.
    fn cost_bitwise_left_shift(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_bitwise_right_shift(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // ── Type conversions: n = 1 (constant) or n = string_chars (NativeFunction205) ───

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

    // Bench: string-to-int?/uint? string_chars=[1..20]; fit: ~5,700 instrs/char + 3.0M base.
    // n=1: 31 units; n=16: 32 units. linear(n >> 4, 1, 31): max error 0.
    // n here is string_chars via NativeFunction205 (serialized_size ≈ char_count).
    fn cost_string_to_int(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    fn cost_string_to_uint(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }

    // Bench: int-to-ascii/utf8 → 31 units constant (output size is small, n=1).
    fn cost_int_to_ascii(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }
    fn cost_int_to_utf8(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // Bench: is-standard → 31 units constant.
    fn cost_is_standard(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // ── Option / response constructors and predicates: all constant 31 ───────────────
    // Bench: some, ok, err, default-to, unwrap!, unwrap-err!, unwrap-panic,
    //        unwrap-err-panic, is-ok, is-none, is-err, is-some, try!
    //        all measured at ~3.0M instrs → 31 cost units.

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

    // Bench: match/ok, match/err, match/some, match/none → SpecialFunction; n=1 → 31 units.
    fn cost_match(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // ── Principal ops: bench shows ~3.1M instrs → 32 cost units ──────────────────────

    fn cost_principal_construct(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }
    fn cost_principal_destruct(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }

    // ── Tuple construction / access: n = field_count ──────────────────────────────────

    // Bench: tuple/tuple-bool field_count=[1..32]; fit: 20,524 instrs/field + 3,009,601 base.
    // n=1: 3,030,125 instrs → 31 units; n=32: 3,671,875 → 38 units.
    // linear(n >> 2, 1, 31): 1 unit per 4 fields + 31. Max error ±1.
    fn cost_tuple_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 31)))
    }

    // Bench: get/tuple-uint field_count=[1..32]; fit: 19,555 instrs/field + 3,027,264 base.
    // n=1: 3,048,411 → 32; n=32: 3,652,756 → 38.
    // linear(n >> 2, 1, 32): 1 unit per 4 fields + 32. Max error ±2.
    fn cost_tuple_get(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 32)))
    }

    // Bench: merge/tuple total_field_count=[1..32]; same slope as get.
    // n=1: 3,094,075 → 32; n=32: 3,694,126 → 38.
    // linear(n >> 2, 1, 32): max error ±2.
    fn cost_tuple_merge(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 32)))
    }

    // ── let: n = binding_count ────────────────────────────────────────────────────────

    // Bench: let/uint binding_count=[1..32]; fit: 18,289 instrs/binding + 3,018,689 base.
    // n=1: 3,037,411 → 31; n=32: 3,601,234 → 37.
    // linear(n >> 3, 1, 32): 1 unit per 8 bindings + 32. Max error ±2.
    fn cost_let(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 3, 1, 32)))
    }

    // ── begin: n = arg_count ──────────────────────────────────────────────────────────

    // Bench: begin (evaluated with uint args); same slope as + (5,793 instrs/arg).
    // linear(n >> 4, 1, 31): same formula as +/*.
    fn cost_begin(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }

    // ── Boolean short-circuit: n = arg_count (SpecialFunction) ───────────────────────

    // Bench: and/bool arg_count=[1..128]; fit: 5,793 instrs/arg + 3,012,293 base.
    // or/bool: 5,501 instrs/arg (similar slope). Both use linear(n >> 4, 1, 31).
    fn cost_and(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }
    fn cost_or(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }

    // ── Higher-order sequence operations: n = list_length (SpecialFunction) ──────────
    // The bench measures total execution of (map/filter/fold f list) including callback
    // invocations.  The slope includes per-element callback overhead.

    // Bench: map/list-optional-uint (worst case) list_length=[1..1000]; 27,358 instrs/elem.
    // n=1: ~31 units; n=1000: ~315 units.
    // linear(n >> 2, 1, 32): 1 unit per 4 elements + 32. At n=1000: 282 (10% under worst).
    fn cost_map(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 32)))
    }

    // Bench: filter/list-optional-uint (worst case); 26,890 instrs/elem.  Same formula.
    fn cost_filter(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 2, 1, 32)))
    }

    // Bench: fold/list-bool (worst measured); 9,604 instrs/elem.
    // n=1000: ~131 units. linear(n >> 3, 1, 32) gives 157 (20% over). Acceptable.
    fn cost_fold(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 3, 1, 32)))
    }

    // Bench: list/bool — SpecialFunction; no separate measurement.
    // Calibrated same as + since list construction iterates arg_count elements.
    fn cost_list_cons(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }

    // ── Sequence operations ───────────────────────────────────────────────────────────
    // NOTE on n semantics: the runtime passes element_size (bytes) for append,
    // total_bytes for concat/replace-at, and 0 or args.len() for len/element-at/
    // index-of/slice/as-max-len.  Bench dimensions are list_length or buffer_bytes,
    // not the runtime n.  Formulas are calibrated from buffer variants where the
    // byte-based n matches bench dimension directly; list variants with complex
    // element types may be undercharged.

    // Bench: len/{buffer,list-*} at min size → 31 units; n=1 always at runtime.
    fn cost_len(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // Bench: element-at/{buffer,list-*} at min size → 31 units; n=args.len()=2 at runtime.
    fn cost_element_at(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // Bench: index-of/{buffer,list-*} at min size → 31 units; n=args.len()=2 at runtime.
    fn cost_index_of(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // Bench: slice?/buffer → 31 units constant; n=0 at runtime (sequences.rs).
    fn cost_slice(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // Bench: as-max-len?/{buffer,list-*} → 31 units at min size; n=0 at runtime.
    fn cost_as_max_len(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(31))
    }

    // Bench: append/list-bool at list_length=1 → 31 units; n = element_type.size() at runtime.
    // bool: n=1 → 31 ✓; optional-uint: n=17 → (17>>4)*1+31=32 ✓.
    fn cost_append(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 4, 1, 31)))
    }

    // Bench: concat/buffer buffer_bytes=[1..1024]; n = total_bytes of both sequences at runtime.
    // At buffer_bytes=1024: n = 2*(1024+5) = 2058.  linear(2058>>10, 1, 31) = 2+31=33 ✓ (bench: 33).
    // List variants with many small elements may be undercharged due to element-count vs byte mismatch.
    fn cost_concat(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 10, 1, 31)))
    }

    // Bench: replace-at?/buffer buffer_bytes=[1..1024]; fit: 164 instrs/byte + 3,030,435 base.
    // n = sequence.size() bytes at runtime.  linear(n >> 9, 1, 31): n=1024 → 2+31=33 ✓ (bench: 33).
    fn cost_replace_at(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 31)))
    }

    // ── Equality: n = sum of serialized sizes of all args (NativeFunction205) ─────────

    // Bench: is-eq/bool → 31; is-eq/buffer at 1024 → 35; is-eq/list-optional-uint at 1000 → 537.
    // n = serialized_size(a) + serialized_size(b) for each argument pair.
    // Scalar (two uint128): n = 34; linear(34>>8, 4, 31) = 0+31=31 ✓.
    // list-optional-uint 1000 elems: n ≈ 38,010; linear(148, 4, 31) = 623 (16% over 537).
    // Overcharges buffer equality (~2× at 1024 bytes) to cover worst-case list types.
    fn cost_eq(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 8, 4, 31)))
    }

    // ── Print: n = serialized size of value (NativeFunction205) ──────────────────────

    // Bench: print/buffer buffer_bytes=[1..1024]; fit: 163 instrs/byte + 3,021,206 base.
    // n = serialized_size(value).  n=1: 31 ✓; n=1029 (1024-byte buf): linear(2,1,31)=33 ✓.
    fn cost_print(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 31)))
    }

    // ── Consensus buffer serialization ───────────────────────────────────────────────

    // Bench: to-consensus-buff? buffer_bytes=[1..1024]; fit: ~163 instrs/byte + base.
    // n = serialized_size of argument (NativeFunction205).
    // n=17 (uint128): linear(0, 1, 31)=31 ✓; n=1029 (1024-byte buf): linear(2,1,31)=33 ✓.
    fn cost_to_consensus_buff(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 31)))
    }

    // Bench: from-consensus-buff?/buffer → constant 32 across all sizes.
    fn cost_from_consensus_buff(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }

    // ── Hash functions: n = buffer_bytes (NativeFunction205, serialized_size) ─────────

    // Bench: hash160/buffer buffer_bytes=[1..1024]; fit: ~70 instrs/byte + 3,025,046 base.
    // n=1: 31 units; n=1024: 35 units.  linear(n >> 8, 1, 30): max error ±1.
    fn cost_hash160(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 8, 1, 30)))
    }

    // Bench: sha256/buffer; same slope as hash160.  linear(n >> 8, 1, 30).
    fn cost_sha256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 8, 1, 30)))
    }

    // Bench: sha512/buffer → constant 32 across all sizes (hardware-accelerated).
    fn cost_sha512(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }

    // Bench: sha512/256 → constant 32 across all sizes.
    fn cost_sha512t256(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }

    // Bench: keccak256/buffer; same slope as hash160.  linear(n >> 8, 1, 30).
    fn cost_keccak256(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 8, 1, 30)))
    }

    // ── secp256k1 / secp256r1 / ed25519 ──────────────────────────────────────────────

    // Bench: secp256k1-recover? → 32 units constant (3,085,000 instrs).
    fn cost_secp256k1recover(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }

    // Bench: secp256k1-verify → 32 units constant.
    fn cost_secp256k1verify(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }

    // Bench: secp256r1-verify/fixed-inputs → 3,055,307 instrs → 32 units constant.
    fn cost_secp256r1verify(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }

    // ── Map / var store operations ────────────────────────────────────────────────────
    // n = value byte size.  Runtime updated from bench; read_count/read_length/
    // write_count/write_length kept from Costs3 (accounting for actual MARF bytes).

    // Bench: map-get?/buffer → near-constant 4,259,721 instrs = 44 units across all sizes.
    fn cost_fetch_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: 44,
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    // Bench: map-set/buffer; fit: 563 instrs/byte + 4,301,893 base.
    // n=1: ~4.30M → 45; n=512: ~4.59M → 47.6; n=1024: ~4.88M → 50.
    // linear(n >> 9, 3, 45): 3 units per 512 bytes + 45.  Max error ±1.
    fn cost_set_entry(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: linear(n >> 9, 3, 45),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 0,
        })
    }

    // Bench: var-get/buffer; fit: 313 instrs/byte + 4,289,144 base.
    // n=1: 44; n=512: 46; n=1024: 48.  linear(n >> 9, 2, 44).
    fn cost_fetch_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: linear(n >> 9, 2, 44),
            write_length: 0,
            write_count: 0,
            read_count: 1,
            read_length: linear(n, 1, 1),
        })
    }

    // Bench: var-set/buffer; fit: 839 instrs/byte + 4,329,201 base.
    // n=1: 45; n=512: 49; n=1024: 53.  linear(n >> 9, 4, 45).
    fn cost_set_var(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost {
            runtime: linear(n >> 9, 4, 45),
            write_length: linear(n, 1, 1),
            write_count: 1,
            read_count: 1,
            read_length: 0,
        })
    }

    // ── State-dependent / not calibrated by bench: forward to Costs4 ─────────────────

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
    fn cost_burn_block_info(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_burn_block_info(n)
    }
    fn cost_stx_account(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_stx_account(n)
    }
    fn cost_stx_transfer_memo(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_stx_transfer_memo(n)
    }
    fn cost_as_contract(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_as_contract(n)
    }

    // ── Clarity 4 / 5 functions ───────────────────────────────────────────────────────

    // cost_contract_hash requires state; forward to Costs4.
    fn cost_contract_hash(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_contract_hash(n)
    }

    // Bench: to-ascii?/string-utf8 string_chars=[1..1024]; fit: ~1,757 instrs/char + 3,022,803 base.
    // n=1: 31; n=64: 33; n=256: 36; n=1024: 50.
    // linear(n >> 6, 1, 32): 1 unit per 64 chars + 32. Max error ±2.
    fn cost_to_ascii(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 6, 1, 32)))
    }

    // restrict-assets and as-contract-safe require state or are not calibrated; forward.
    fn cost_restrict_assets(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_restrict_assets(n)
    }
    fn cost_as_contract_safe(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Costs4::cost_as_contract_safe(n)
    }

    // ── Clarity 6 functions ───────────────────────────────────────────────────────────

    // Bench (clarity-cost-bench): sibling_count=[1,2,4,8,16,24]
    //   n=1: 3,075,946 instrs → 32 units; n=8: 3,178,743 → 33; n=16: 3,296,977 → 34; n=24: 3,417,129 → 35
    //   Linear fit: 14,834 instrs/sibling + 3,061,000 base; 0.1537 units/sibling + 31.7 base
    //   (calibration: 1 cost unit = 96,528 instrs, derived from +/uint at n=32)
    //   linear(n >> 3, 1, 32): 1 unit per 8 siblings + 32 — matches all measured points exactly.
    fn cost_verify_merkle_proof(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 3, 1, 32)))
    }

    // Bench (clarity-cost-bench): buffer_bytes=[1,4,16,64,256,512,1024]
    //   n=1: 3,024,835 instrs → 31 units; n=256: 3,065,451 → 32; n=512: 3,127,562 → 32; n=1024: 3,207,990 → 33
    //   Linear fit: 179 instrs/byte + 3,027,000 base; ~2 units per KiB + 31 base
    //   (calibration: 1 cost unit = 96,528 instrs, derived from +/uint at n=32)
    //   linear(n >> 10, 2, 31): 2 units per KiB + 31 — matches n=1→31, n=1024→33.
    fn cost_get_bitcoin_tx_output(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 10, 2, 31)))
    }

    // Bench (clarity-cost-bench): buffer_bytes=[1,4,16,64,256,512,1024]
    //   n=1: 3,090,846 instrs → 32 units; n=512: 3,174,831 → 33; n=1024: 3,268,215 → 34
    //   Curve fit: O(n·log n), effectively ~173 instrs/byte in measured range + 3,091,000 base
    //   (calibration: 1 cost unit = 96,528 instrs, derived from +/uint at n=32)
    //   linear(n >> 9, 1, 32): 1 unit per 512 bytes + 32 — matches n=512→33, n=1024→34 exactly.
    fn cost_ed25519verify(n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(linear(n >> 9, 1, 32)))
    }

    // Bench (clarity-cost-bench): ignored=[1] (n is unused; compressed key is always 33 bytes)
    //   n=1: 3,083,667 instrs → 32 units
    //   (calibration: 1 cost unit = 96,528 instrs, derived from +/uint at n=32)
    fn cost_secp256k1decompress(_n: u64) -> Result<ExecutionCost, VmExecutionError> {
        Ok(ExecutionCost::runtime(32))
    }
}
