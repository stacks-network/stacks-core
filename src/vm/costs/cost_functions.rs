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
def_runtime_cost!(ASSERTS { Constant(1) });
def_runtime_cost!(MAP { Constant(1) });
def_runtime_cost!(FILTER { Constant(1) });
def_runtime_cost!(LEN { Constant(1) });
def_runtime_cost!(FOLD { Constant(1) });
def_runtime_cost!(LIST_CONS { Linear(1, 1) });
def_runtime_cost!(TYPE_PARSE_STEP { Constant(1) });
def_runtime_cost!(DATA_HASH_COST { Linear(1, 1) });


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
def_runtime_cost!(XOR { Constant(1) });
def_runtime_cost!(NOT { Constant(1) });
def_runtime_cost!(EQ { Linear(1, 1) });
def_runtime_cost!(BEGIN { Constant(1) });
def_runtime_cost!(HASH160 { Constant(1) });
def_runtime_cost!(SHA256 { Constant(1) });
def_runtime_cost!(SHA512 { Constant(1) });
def_runtime_cost!(SHA512T256 { Constant(1) });
def_runtime_cost!(KECCAK256 { Constant(1) });
def_runtime_cost!(PRINT { Constant(1) });
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
