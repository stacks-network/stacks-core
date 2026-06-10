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

use diesel::prelude::*;

table! {
    network (id) {
        id -> Integer,
        name -> Text,
    }
}

table! {
    chainstate (id) {
        id -> Integer,
        network_id -> Integer,
        chain_id -> BigInt,
        tip_index_hash -> Binary,
        tip_height -> BigInt,
        epochs_hash -> Binary,
    }
}

table! {
    epoch (id) {
        id -> Integer,
        chainstate_id -> Integer,
        stacks_epoch_id -> Integer,
        network_epoch_id -> Integer,
        start_height -> BigInt,
        end_height -> BigInt,
        write_length_budget -> BigInt,
        write_count_budget -> BigInt,
        read_length_budget -> BigInt,
        read_count_budget -> BigInt,
        runtime_budget -> BigInt,
    }
}

table! {
    stacks_tx_type (id) {
        id -> Integer,
        name -> Text,
    }
}

table! {
    principal (id) {
        id -> Integer,
        address -> Text,
    }
}

table! {
    contract (id) {
        id -> Integer,
        issuer_principal_id -> Integer,
        name -> Text,
    }
}

table! {
    contract_fn (id) {
        id -> Integer,
        contract_id -> Integer,
        name -> Text,
    }
}

table! {
    burn_block (id) {
        id -> BigInt,
        block_hash -> Binary,
        block_hash_hex -> Text,
        height -> BigInt,
    }
}

table! {
    stacks_block (id) {
        id -> BigInt,
        index_hash -> Binary,
        block_hash -> Binary,
        block_hash_hex -> Text,
        height -> BigInt,
        parent_stacks_block_id -> Nullable<BigInt>,
        burn_block_id -> BigInt,
        txs_indexed -> Bool,
    }
}

table! {
    _staged_stacks_block (index_hash) {
        index_hash -> Binary,
        block_hash -> Binary,
        parent_index_hash -> Binary,
        height -> BigInt,
        burn_block_hash -> Binary,
        burn_block_height -> BigInt,
    }
}

table! {
    _staged_indexed_stacks_block (block_index_hash) {
        block_index_hash -> Binary,
    }
}

table! {
    synthetic_block (id) {
        id -> BigInt,
        stacks_block_id -> BigInt,
        index_hash -> Binary,
    }
}

table! {
    stacks_tx (id) {
        id -> BigInt,
        stacks_block_id -> BigInt,
        tx_hash -> Binary,
        tx_hash_hex -> Text,
        stacks_tx_type_id -> Integer,
        caller_principal_id -> Integer,
        contract_id -> Nullable<Integer>,
        contract_fn_id -> Nullable<Integer>,
        contract_call_args_json -> Nullable<Text>,
    }
}

table! {
    _staged_stacks_tx (block_index_hash, tx_hash) {
        block_index_hash -> Binary,
        tx_hash -> Binary,
        stacks_tx_type_id -> Integer,
        caller_address -> Text,
        contract_issuer_address -> Nullable<Text>,
        contract_name -> Nullable<Text>,
        contract_fn_name -> Nullable<Text>,
        contract_call_args_json -> Nullable<Text>,
    }
}

table! {
    benchmark_run (id) {
        id -> Integer,
        run_name -> Nullable<Text>,
        chainstate_id -> Integer,
        git_commit_hash -> Binary,
        start_time -> Timestamp,
        end_time -> Nullable<Timestamp>,
        args_json -> Text,
        build_profile -> Text,
        build_opt_level -> Text,
        build_debug_assertions -> Bool,
        build_overflow_checks -> Bool,
        build_target_triple -> Text,
        build_rustc_version -> Text,
        git_branch -> Nullable<Text>,
        git_dirty -> Nullable<Bool>,
    }
}

table! {
    block_processing_baseline (benchmark_run_id) {
        benchmark_run_id -> Integer,
        start_parent_index_hash -> Binary,
        warmup_blocks -> Integer,
        measured_blocks -> Integer,
        avg_setup_us -> Integer,
        avg_finalize_us -> Integer,
        avg_clarity_commit_us -> Integer,
        avg_advance_tip_us -> Integer,
        avg_index_commit_us -> Integer,
    }
}

table! {
    stacks_block_stats (benchmark_run_id, synthetic_block_id) {
        benchmark_run_id -> Integer,
        synthetic_block_id -> BigInt,
        total_duration_us -> Integer,
        setup_duration_us -> Integer,
        execution_duration_us -> Integer,
        commit_duration_us -> Integer,
        commit_overhead_baseline_us -> Integer,
        clarity_write_length -> Integer,
        clarity_write_count -> Integer,
        clarity_read_length -> Integer,
        clarity_read_count -> Integer,
        clarity_runtime -> Integer,
        total_storage_delta -> BigInt,
    }
}

table! {
    stacks_tx_stats (benchmark_run_id, synthetic_block_id, stacks_tx_id) {
        benchmark_run_id -> Integer,
        stacks_tx_id -> BigInt,
        synthetic_block_id -> BigInt,
        duration_us -> Integer,
        clarity_write_length -> Integer,
        clarity_write_count -> Integer,
        clarity_read_length -> Integer,
        clarity_read_count -> Integer,
        clarity_runtime -> Integer,
    }
}

table! {
    profiler_location (id) {
        id -> Integer,
        file -> Text,
        line -> Integer,
    }
}

table! {
    profiler_span (id) {
        id -> Integer,
        name -> Text,
        context -> Nullable<Text>,
    }
}

table! {
    profiler_tag (id) {
        id -> Integer,
        tag -> Text,
    }
}

table! {
    profiler_record (id) {
        id -> BigInt,
        benchmark_run_id -> Integer,
        parent_id -> Nullable<BigInt>,
        profiler_span_id -> Integer,
        profiler_tag_id -> Nullable<Integer>,
        profiler_location_id -> Integer,
        child_index -> Integer,
        depth -> Integer,
        synthetic_block_id -> BigInt,
        stacks_tx_id -> Nullable<BigInt>,
        wall_time_us -> BigInt,
        cpu_time_us -> BigInt,
        self_wall_time_us -> BigInt,
        self_cpu_time_us -> BigInt,
        call_count -> Integer,
        sample_count -> Integer,
    }
}

table! {
    profiler_kv_value_type (id) {
        id -> Integer,
        name -> Text,
    }
}

table! {
    profiler_kv_key (id) {
        id -> Integer,
        key -> Text,
    }
}

table! {
    profiler_kv_value (id) {
        id -> Integer,
        profiler_kv_value_type_id -> Integer,
        value -> Text,
    }
}

table! {
    profiler_record_kv (profiler_record_id, profiler_kv_key_id, profiler_kv_value_id) {
        profiler_record_id -> BigInt,
        profiler_kv_key_id -> Integer,
        profiler_kv_value_id -> Integer,
        count -> Integer,
    }
}

table! {
    profiler_record_clarity_costs (profiler_record_id) {
        profiler_record_id -> BigInt,
        runtime -> BigInt,
        read_count -> BigInt,
        read_length -> BigInt,
        write_count -> BigInt,
        write_length -> BigInt,
        input_n -> BigInt,
    }
}

table! {
    _staged_profiler_record_clarity_costs (profiler_record_id) {
        profiler_record_id -> BigInt,
        runtime -> BigInt,
        read_count -> BigInt,
        read_length -> BigInt,
        write_count -> BigInt,
        write_length -> BigInt,
        input_n -> BigInt,
    }
}

table! {
    _staged_profiler_record_kv (profiler_record_id, key, value_type_id, value) {
        profiler_record_id -> BigInt,
        key -> Text,
        value_type_id -> Integer,
        value -> Text,
        count -> Integer,
    }
}

table! {
    chain_tip_cache (tip_index_hash, height) {
        tip_index_hash -> Binary,
        height -> BigInt,
        index_hash -> Binary,
    }
}

joinable!(chainstate -> network (network_id));
joinable!(epoch -> chainstate (chainstate_id));
joinable!(benchmark_run -> chainstate (chainstate_id));
joinable!(stacks_block -> burn_block (burn_block_id));
joinable!(synthetic_block -> stacks_block (stacks_block_id));
joinable!(stacks_tx -> stacks_block (stacks_block_id));
joinable!(stacks_tx -> stacks_tx_type (stacks_tx_type_id));
joinable!(stacks_tx -> principal (caller_principal_id));
joinable!(stacks_tx -> contract (contract_id));
joinable!(stacks_tx -> contract_fn (contract_fn_id));
joinable!(contract_fn -> contract (contract_id));
joinable!(block_processing_baseline -> benchmark_run (benchmark_run_id));
joinable!(stacks_block_stats -> benchmark_run (benchmark_run_id));
joinable!(stacks_block_stats -> synthetic_block (synthetic_block_id));
joinable!(stacks_tx_stats -> synthetic_block (synthetic_block_id));
joinable!(stacks_tx_stats -> benchmark_run (benchmark_run_id));
joinable!(stacks_tx_stats -> stacks_tx (stacks_tx_id));
joinable!(profiler_record -> benchmark_run (benchmark_run_id));
joinable!(profiler_record -> profiler_span (profiler_span_id));
joinable!(profiler_record -> profiler_location (profiler_location_id));
joinable!(profiler_record -> profiler_tag (profiler_tag_id));
joinable!(profiler_record -> synthetic_block (synthetic_block_id));
joinable!(profiler_record -> stacks_tx (stacks_tx_id));
joinable!(profiler_kv_value -> profiler_kv_value_type (profiler_kv_value_type_id));
joinable!(profiler_record_kv -> profiler_record (profiler_record_id));
joinable!(profiler_record_kv -> profiler_kv_key (profiler_kv_key_id));
joinable!(profiler_record_kv -> profiler_kv_value (profiler_kv_value_id));
joinable!(profiler_record_clarity_costs -> profiler_record (profiler_record_id));

allow_tables_to_appear_in_same_query!(
    network,
    chainstate,
    epoch,
    stacks_tx_type,
    principal,
    contract,
    contract_fn,
    burn_block,
    stacks_block,
    synthetic_block,
    stacks_tx,
    benchmark_run,
    block_processing_baseline,
    stacks_block_stats,
    stacks_tx_stats,
    _staged_stacks_block,
    _staged_indexed_stacks_block,
    _staged_stacks_tx,
    profiler_location,
    profiler_span,
    profiler_tag,
    profiler_record,
    profiler_kv_value_type,
    profiler_kv_key,
    profiler_kv_value,
    profiler_record_kv,
    profiler_record_clarity_costs,
    _staged_profiler_record_clarity_costs,
    _staged_profiler_record_kv,
    chain_tip_cache,
);
