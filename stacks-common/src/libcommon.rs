#![allow(unused_macros)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![cfg_attr(test, allow(unused_variables, unused_assignments))]

extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate rand;
extern crate rusqlite;
extern crate secp256k1;
extern crate serde;
#[macro_use]
extern crate lazy_static;
extern crate ripemd;
extern crate sha2;
extern crate sha3;
extern crate time;

#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;
extern crate chrono;
#[cfg(feature = "slog_json")]
extern crate slog_json;
extern crate slog_term;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

#[macro_use]
pub mod util;

#[macro_use]
pub mod codec;

pub mod types;

pub mod address;

pub mod deps_common;

use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksBlockId};

pub mod consts {
    use crate::types::chainstate::BlockHeaderHash;
    use crate::types::chainstate::ConsensusHash;

    pub const TOKEN_TRANSFER_MEMO_LENGTH: usize = 34; // same as it is in Stacks v1

    pub const BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT: u64 = 0;
    pub const BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP: u32 = 0;
    pub const BITCOIN_REGTEST_FIRST_BLOCK_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub const FIRST_STACKS_BLOCK_HASH: BlockHeaderHash = BlockHeaderHash([0u8; 32]);

    pub const FIRST_BURNCHAIN_CONSENSUS_HASH: ConsensusHash = ConsensusHash([0u8; 20]);
}
