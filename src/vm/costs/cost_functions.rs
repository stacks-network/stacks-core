// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
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

use super::CostFunctions::{Constant, Linear, LogN, NLogN};
use super::{SimpleCostSpecification, TypeCheckCost};

macro_rules! def_runtime_cost {
    ($Name:ident { $runtime:expr }) => {
        pub const $Name: SimpleCostSpecification = SimpleCostSpecification {
            write_length: Constant(0),
            write_count: Constant(0),
            read_count: Constant(0),
            read_length: Constant(0),
            runtime: $runtime,
        };
    };
}

def_runtime_cost!(ANALYSIS_TYPE_ANNOTATE { Linear(1, 1) });
def_runtime_cost!(ANALYSIS_TYPE_CHECK { Linear(1, 1) });
def_runtime_cost!(ANALYSIS_TYPE_LOOKUP { Linear(1, 1) });
def_runtime_cost!(ANALYSIS_VISIT { Constant(1) });
def_runtime_cost!(ANALYSIS_ITERABLE_FUNC { Constant(1) });
def_runtime_cost!(ANALYSIS_OPTION_CONS { Constant(1) });
def_runtime_cost!(ANALYSIS_OPTION_CHECK { Constant(1) });
def_runtime_cost!(ANALYSIS_BIND_NAME { Linear(1, 1) });
def_runtime_cost!(ANALYSIS_LIST_ITEMS_CHECK { Linear(1, 1) });
def_runtime_cost!(ANALYSIS_CHECK_TUPLE_GET { LogN(1, 1) });
def_runtime_cost!(ANALYSIS_CHECK_TUPLE_CONS { NLogN(1, 1) });
def_runtime_cost!(ANALYSIS_TUPLE_ITEMS_CHECK { Linear(1, 1) });
def_runtime_cost!(ANALYSIS_CHECK_LET { Linear(1, 1) });

def_runtime_cost!(ANALYSIS_LOOKUP_FUNCTION { Constant(1) });
def_runtime_cost!(ANALYSIS_LOOKUP_FUNCTION_TYPES { Linear(1, 1) });

def_runtime_cost!(ANALYSIS_LOOKUP_VARIABLE_CONST { Constant(1) });
def_runtime_cost!(ANALYSIS_LOOKUP_VARIABLE_DEPTH { NLogN(1, 1) });

def_runtime_cost!(AST_PARSE { Linear(1, 1) });
def_runtime_cost!(AST_CYCLE_DETECTION { Linear(1, 1) });

pub const ANALYSIS_STORAGE: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const ANALYSIS_USE_TRAIT_ENTRY: SimpleCostSpecification = SimpleCostSpecification {
    // increases the total storage consumed by the contract!
    //  so we count the additional write_length, but since it does _not_ require
    //  an additional _write_, we don't charge for that.
    write_length: Linear(1, 1),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Linear(1, 1),
};

pub const ANALYSIS_GET_FUNCTION_ENTRY: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Linear(1, 1),
};

pub const ANALYSIS_FETCH_CONTRACT_ENTRY: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Linear(1, 1),
};

def_runtime_cost!(LOOKUP_VARIABLE_DEPTH { Linear(1, 1) });
def_runtime_cost!(LOOKUP_VARIABLE_SIZE { Linear(1, 0) });
def_runtime_cost!(LOOKUP_FUNCTION { Constant(1) });
def_runtime_cost!(BIND_NAME { Constant(1) });
def_runtime_cost!(INNER_TYPE_CHECK_COST { Linear(1, 1) });
def_runtime_cost!(USER_FUNCTION_APPLICATION { Linear(1, 1) });

def_runtime_cost!(LET { Linear(1, 1) });
def_runtime_cost!(IF { Constant(1) });
def_runtime_cost!(ASSERTS { Constant(1) });
def_runtime_cost!(MAP { Constant(1) });
def_runtime_cost!(FILTER { Constant(1) });
def_runtime_cost!(LEN { Constant(1) });
def_runtime_cost!(FOLD { Constant(1) });
def_runtime_cost!(LIST_CONS { Linear(1, 1) });
def_runtime_cost!(TYPE_PARSE_STEP { Constant(1) });
def_runtime_cost!(DATA_HASH_COST { Linear(1, 1) });
def_runtime_cost!(TUPLE_GET { NLogN(1, 1) });
def_runtime_cost!(TUPLE_CONS { NLogN(1, 1) });

def_runtime_cost!(ADD { Linear(1, 1) });
def_runtime_cost!(SUB { Linear(1, 1) });
def_runtime_cost!(MUL { Linear(1, 1) });
def_runtime_cost!(DIV { Linear(1, 1) });
def_runtime_cost!(GEQ { Constant(1) });
def_runtime_cost!(LEQ { Constant(1) });
def_runtime_cost!(LE  { Constant(1) });
def_runtime_cost!(GE  { Constant(1) });
def_runtime_cost!(INT_CAST { Constant(1) });
def_runtime_cost!(MOD { Constant(1) });
def_runtime_cost!(POW { Constant(1) });
def_runtime_cost!(SQRTI { Constant(1) });
def_runtime_cost!(XOR { Constant(1) });
def_runtime_cost!(NOT { Constant(1) });
def_runtime_cost!(EQ { Linear(1, 1) });
def_runtime_cost!(BEGIN { Constant(1) });
def_runtime_cost!(HASH160 { Constant(1) });
def_runtime_cost!(SHA256 { Constant(1) });
def_runtime_cost!(SHA512 { Constant(1) });
def_runtime_cost!(SHA512T256 { Constant(1) });
def_runtime_cost!(KECCAK256 { Constant(1) });
def_runtime_cost!(SECP256K1RECOVER { Constant(1) });
def_runtime_cost!(SECP256K1VERIFY { Constant(1) });
def_runtime_cost!(PRINT { Linear(1, 1) });
def_runtime_cost!(SOME_CONS { Constant(1) });
def_runtime_cost!(OK_CONS { Constant(1) });
def_runtime_cost!(ERR_CONS { Constant(1) });
def_runtime_cost!(DEFAULT_TO { Constant(1) });
def_runtime_cost!(UNWRAP_RET { Constant(1) });
def_runtime_cost!(UNWRAP_ERR_OR_RET { Constant(1) });
def_runtime_cost!(IS_OKAY { Constant(1) });
def_runtime_cost!(IS_NONE { Constant(1) });
def_runtime_cost!(IS_ERR { Constant(1) });
def_runtime_cost!(IS_SOME { Constant(1) });
def_runtime_cost!(UNWRAP { Constant(1) });
def_runtime_cost!(UNWRAP_ERR { Constant(1) });
def_runtime_cost!(TRY_RET { Constant(1) });
def_runtime_cost!(MATCH { Constant(1) });
def_runtime_cost!(OR { Linear(1, 1) });
def_runtime_cost!(AND { Linear(1, 1) });

def_runtime_cost!(APPEND { Linear(1, 1) });
def_runtime_cost!(CONCAT { Linear(1, 1) });
def_runtime_cost!(AS_MAX_LEN { Constant(1) });

def_runtime_cost!(CONTRACT_CALL { Constant(1) });
def_runtime_cost!(CONTRACT_OF { Constant(1) });
def_runtime_cost!(PRINCIPAL_OF { Constant(1) });

pub const AT_BLOCK: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Constant(1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const LOAD_CONTRACT: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Linear(1, 1),
};

pub const CREATE_MAP: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(0),
    read_length: Constant(0),
};

pub const CREATE_VAR: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(2),
    runtime: Linear(1, 1),
    read_count: Constant(0),
    read_length: Constant(0),
};

pub const CREATE_NFT: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(0),
    read_length: Constant(0),
};

pub const CREATE_FT: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(2),
    runtime: Constant(1),
    read_count: Constant(0),
    read_length: Constant(0),
};

pub const FETCH_ENTRY: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Linear(1, 1),
};

pub const SET_ENTRY: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(0),
};

pub const FETCH_VAR: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Linear(1, 1),
};

pub const SET_VAR: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(0),
};

pub const CONTRACT_STORAGE: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(0),
    read_length: Constant(0),
};

pub const BLOCK_INFO: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Constant(1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const STX_BALANCE: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Constant(1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const STX_TRANSFER: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(1),
    runtime: Constant(1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const FT_MINT: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(2),
    runtime: Constant(1),
    read_count: Constant(2),
    read_length: Constant(1),
};

pub const FT_TRANSFER: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(2),
    runtime: Constant(1),
    read_count: Constant(2),
    read_length: Constant(1),
};

pub const FT_BALANCE: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Constant(1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const NFT_MINT: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const NFT_TRANSFER: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const NFT_OWNER: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(1),
};

pub const TYPE_CHECK_COST: TypeCheckCost = TypeCheckCost {};
