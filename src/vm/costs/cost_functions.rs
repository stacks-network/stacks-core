use super::{SimpleCostSpecification, TypeCheckCost};
use super::CostFunctions::{Linear, Constant, NLogN};

macro_rules! def_runtime_cost {
    ($Name:ident { $runtime:expr }) => {
        pub const $Name: SimpleCostSpecification = 
            SimpleCostSpecification {
                write_length: Constant(0),
                write_count: Constant(0),
                read_count: Constant(0),
                read_length: Constant(0),
                runtime: $runtime
            };
    }
}

def_runtime_cost!(LOOKUP_VARIABLE { Linear(1, 1) });
def_runtime_cost!(LOOKUP_FUNCTION { Constant(1) });
def_runtime_cost!(BIND_NAME { Constant(1) });
def_runtime_cost!(INNER_TYPE_CHECK_COST { Linear(1, 1) });
def_runtime_cost!(USER_FUNCTION_APPLICATION { Linear(1, 1) });

def_runtime_cost!(LET { Linear(1, 1) });
def_runtime_cost!(IF { Constant(1) });
def_runtime_cost!(TYPE_PARSE_STEP { Constant(1) });
def_runtime_cost!(DATA_HASH_COST { Linear(1, 1) });


pub const FETCH_ENTRY: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Linear(1, 1)
};

pub const SET_ENTRY: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(0)
};

pub const FETCH_VAR: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Linear(1, 1)
};

pub const SET_VAR: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(0)
};

pub const CONTRACT_STORAGE: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Linear(1, 1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(0),
    read_length: Constant(0) };

pub const BLOCK_INFO: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Constant(1),
    read_count: Constant(1),
    read_length: Constant(1) };

pub const STX_TRANSFER: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(1),
    runtime: Constant(1),
    read_count: Constant(1),
    read_length: Constant(1) };

pub const FT_MINT: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(2),
    runtime: Constant(1),
    read_count: Constant(2),
    read_length: Constant(1) };

pub const FT_TRANSFER: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(2),
    runtime: Constant(1),
    read_count: Constant(2),
    read_length: Constant(1) };

pub const FT_BALANCE: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Constant(1),
    read_count: Constant(1),
    read_length: Constant(1) };

pub const NFT_MINT: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(1) };

pub const NFT_TRANSFER: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(1),
    write_count: Constant(1),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(1) };

pub const NFT_OWNER: SimpleCostSpecification = SimpleCostSpecification {
    write_length: Constant(0),
    write_count: Constant(0),
    runtime: Linear(1, 1),
    read_count: Constant(1),
    read_length: Constant(1) };

pub const TYPE_CHECK_COST: TypeCheckCost = TypeCheckCost {};
