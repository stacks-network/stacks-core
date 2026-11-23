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

//! The table of host functions (ABI 6.2).

use super::Charge::*;
use super::Group::*;
use super::ParamKind::*;
use super::{HostFunction, Param, ParamKind, ResultKind};
use crate::status::*;

const fn p(name: &'static str, kind: ParamKind) -> Param {
    Param { name, kind }
}

/// Every host function, in the order of ABI 6.2.
pub const HOST_FUNCTIONS: [HostFunction; 66] = [
    // Boundary and control.
    HostFunction {
        name: "args_size",
        group: Boundary,
        params: &[],
        result: ResultKind::I32,
        charges: &[Base],
    },
    HostFunction {
        name: "args_read",
        group: Boundary,
        params: &[p("dst", I32), p("offset", I32), p("len", I32)],
        result: ResultKind::None,
        charges: &[Base, Output("len")],
    },
    HostFunction {
        name: "result_set",
        group: Boundary,
        params: &[p("ok", I32), p("result", Bytes)],
        result: ResultKind::None,
        charges: &[Base, Input("result")],
    },
    HostFunction {
        name: "abort",
        group: Boundary,
        params: &[p("code", I32), p("msg", Bytes)],
        result: ResultKind::None,
        charges: &[Base, Input("msg")],
    },
    // Transaction and block context.
    HostFunction {
        name: "sender",
        group: Context,
        params: &[p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Output("out")],
    },
    HostFunction {
        name: "caller",
        group: Context,
        params: &[p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Output("out")],
    },
    HostFunction {
        name: "sponsor",
        group: Context,
        params: &[p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Output("out")],
    },
    HostFunction {
        name: "contract",
        group: Context,
        params: &[p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Output("out")],
    },
    HostFunction {
        name: "stacks_height",
        group: Context,
        params: &[p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base],
    },
    HostFunction {
        name: "burn_height",
        group: Context,
        params: &[p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base],
    },
    HostFunction {
        name: "tenure_height",
        group: Context,
        params: &[p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base],
    },
    HostFunction {
        name: "time",
        group: Context,
        params: &[p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base],
    },
    HostFunction {
        name: "liquid_supply",
        group: Context,
        params: &[p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base, Read(1)],
    },
    HostFunction {
        name: "chain_id",
        group: Context,
        params: &[p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base],
    },
    HostFunction {
        name: "is_mainnet",
        group: Context,
        params: &[],
        result: ResultKind::Bool,
        charges: &[Base],
    },
    HostFunction {
        name: "is_regtest",
        group: Context,
        params: &[],
        result: ResultKind::Bool,
        charges: &[Base],
    },
    // Block data.
    HostFunction {
        name: "stacks_block_id_header_hash",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(32))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "stacks_block_header_hash",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(32))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "stacks_block_time",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(16))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "tenure_burnchain_header_hash",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(32))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "tenure_miner_address",
        group: BlockData,
        params: &[p("height", U128), p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Output("out")],
    },
    HostFunction {
        name: "tenure_time",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(16))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "tenure_vrf_seed",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(32))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "tenure_block_reward",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(16))],
        result: ResultKind::Status(BlockRewardStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "tenure_miner_spend_total",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(16))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "tenure_miner_spend_winner",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(16))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "burn_block_header_hash",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(32))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "burn_block_pox_addr",
        group: BlockData,
        params: &[p("height", U128), p("index", I32), p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Output("out")],
    },
    HostFunction {
        name: "burn_block_pox_payout",
        group: BlockData,
        params: &[p("height", U128), p("out", Out(16))],
        result: ResultKind::Status(BlockLookupStatus::CODES),
        charges: &[Base],
    },
    // Storage.
    HostFunction {
        name: "kv_get",
        group: Storage,
        params: &[p("key", Bytes), p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Input("key"), Read(1), Stored("out"), Output("out")],
    },
    HostFunction {
        name: "kv_has",
        group: Storage,
        params: &[p("key", Bytes)],
        result: ResultKind::Bool,
        charges: &[Base, Input("key"), Read(1)],
    },
    HostFunction {
        name: "kv_set",
        group: Storage,
        params: &[p("key", Bytes), p("value", Bytes)],
        result: ResultKind::None,
        charges: &[
            Base,
            Input("key"),
            Input("value"),
            Write(1),
            Stored("value"),
        ],
    },
    HostFunction {
        name: "kv_delete",
        group: Storage,
        params: &[p("key", Bytes)],
        result: ResultKind::Bool,
        charges: &[Base, Input("key"), Read(1), Write(1)],
    },
    // Assets.
    HostFunction {
        name: "ft_set_cap",
        group: Assets,
        params: &[p("token", I32), p("cap", U128)],
        result: ResultKind::None,
        charges: &[Base, Read(1), Write(1)],
    },
    HostFunction {
        name: "ft_mint",
        group: Assets,
        params: &[p("token", I32), p("amount", U128), p("to", Principal)],
        result: ResultKind::Status(FtMintStatus::CODES),
        charges: &[Base, Input("to"), Read(3), Write(2)],
    },
    HostFunction {
        name: "ft_burn",
        group: Assets,
        params: &[p("token", I32), p("amount", U128), p("from", Principal)],
        result: ResultKind::Status(FtBurnStatus::CODES),
        charges: &[Base, Input("from"), Read(2), Write(2)],
    },
    HostFunction {
        name: "ft_transfer",
        group: Assets,
        params: &[
            p("token", I32),
            p("amount", U128),
            p("from", Principal),
            p("to", Principal),
        ],
        result: ResultKind::Status(FtTransferStatus::CODES),
        charges: &[Base, Input("from"), Input("to"), Read(2), Write(2)],
    },
    HostFunction {
        name: "ft_balance",
        group: Assets,
        params: &[p("token", I32), p("owner", Principal), p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base, Input("owner"), Read(1)],
    },
    HostFunction {
        name: "ft_supply",
        group: Assets,
        params: &[p("token", I32), p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base, Read(1)],
    },
    HostFunction {
        name: "nft_mint",
        group: Assets,
        params: &[p("token", I32), p("id", Bytes), p("to", Principal)],
        result: ResultKind::Status(NftMintStatus::CODES),
        charges: &[Base, Input("id"), Input("to"), Read(1), Write(1)],
    },
    HostFunction {
        name: "nft_burn",
        group: Assets,
        params: &[p("token", I32), p("id", Bytes), p("from", Principal)],
        result: ResultKind::Status(NftBurnStatus::CODES),
        charges: &[Base, Input("id"), Input("from"), Read(1), Write(1)],
    },
    HostFunction {
        name: "nft_transfer",
        group: Assets,
        params: &[
            p("token", I32),
            p("id", Bytes),
            p("from", Principal),
            p("to", Principal),
        ],
        result: ResultKind::Status(NftTransferStatus::CODES),
        charges: &[
            Base,
            Input("id"),
            Input("from"),
            Input("to"),
            Read(1),
            Write(1),
        ],
    },
    HostFunction {
        name: "nft_owner",
        group: Assets,
        params: &[p("token", I32), p("id", Bytes), p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Input("id"), Read(1), Output("out")],
    },
    HostFunction {
        name: "stx_transfer",
        group: Assets,
        params: &[
            p("amount", U128),
            p("from", Principal),
            p("to", Principal),
            p("memo", Bytes),
        ],
        result: ResultKind::Status(StxTransferStatus::CODES),
        charges: &[
            Base,
            Input("from"),
            Input("to"),
            Input("memo"),
            Read(2),
            Write(2),
        ],
    },
    HostFunction {
        name: "stx_burn",
        group: Assets,
        params: &[p("amount", U128), p("from", Principal)],
        result: ResultKind::Status(StxBurnStatus::CODES),
        charges: &[Base, Input("from"), Read(2), Write(2)],
    },
    HostFunction {
        name: "stx_locked",
        group: Assets,
        params: &[p("owner", Principal), p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base, Input("owner"), Read(1)],
    },
    HostFunction {
        name: "stx_unlock_height",
        group: Assets,
        params: &[p("owner", Principal), p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base, Input("owner"), Read(1)],
    },
    HostFunction {
        name: "stx_unlocked",
        group: Assets,
        params: &[p("owner", Principal), p("out", Out(16))],
        result: ResultKind::None,
        charges: &[Base, Input("owner"), Read(1)],
    },
    // Frames.
    HostFunction {
        name: "frame_open",
        group: Frames,
        params: &[p("kind", I32), p("desc", Bytes)],
        result: ResultKind::None,
        charges: &[Base, Input("desc")],
    },
    HostFunction {
        name: "frame_close",
        group: Frames,
        params: &[p("commit", I32)],
        result: ResultKind::I32,
        charges: &[Base],
    },
    // Calls and principals.
    // The callee's instantiation is charged separately (ABI 9.2).
    HostFunction {
        name: "call",
        group: Calls,
        params: &[
            p("target", Principal),
            p("fn", Bytes),
            p("args", Bytes),
            p("read_only", I32),
            p("out", Buf),
            p("ok", Out(1)),
        ],
        result: ResultKind::Len,
        charges: &[
            Base,
            Input("target"),
            Input("fn"),
            Input("args"),
            Output("out"),
        ],
    },
    HostFunction {
        name: "result_read",
        group: Calls,
        params: &[p("dst", I32), p("offset", I32), p("len", I32)],
        result: ResultKind::None,
        charges: &[Base, Output("len")],
    },
    HostFunction {
        name: "contract_hash",
        group: Calls,
        params: &[p("contract", Principal), p("out", Out(32))],
        result: ResultKind::Status(ContractHashStatus::CODES),
        charges: &[Base, Input("contract"), Read(1)],
    },
    HostFunction {
        name: "principal_to_ascii",
        group: Calls,
        params: &[p("p", Principal), p("out", Buf)],
        result: ResultKind::Len,
        charges: &[Base, Input("p"), Output("out")],
    },
    // Events.
    HostFunction {
        name: "emit",
        group: Events,
        params: &[p("event", I32), p("data", Bytes)],
        result: ResultKind::None,
        charges: &[Base, Input("data")],
    },
    HostFunction {
        name: "log",
        group: Events,
        params: &[p("data", Bytes)],
        result: ResultKind::None,
        charges: &[Base, Input("data")],
    },
    // Cryptography.
    HostFunction {
        name: "sha256",
        group: Crypto,
        params: &[p("data", Bytes), p("out", Out(32))],
        result: ResultKind::None,
        charges: &[Base, Input("data")],
    },
    HostFunction {
        name: "sha512",
        group: Crypto,
        params: &[p("data", Bytes), p("out", Out(64))],
        result: ResultKind::None,
        charges: &[Base, Input("data")],
    },
    HostFunction {
        name: "sha512_256",
        group: Crypto,
        params: &[p("data", Bytes), p("out", Out(32))],
        result: ResultKind::None,
        charges: &[Base, Input("data")],
    },
    HostFunction {
        name: "keccak256",
        group: Crypto,
        params: &[p("data", Bytes), p("out", Out(32))],
        result: ResultKind::None,
        charges: &[Base, Input("data")],
    },
    HostFunction {
        name: "ripemd160",
        group: Crypto,
        params: &[p("data", Bytes), p("out", Out(20))],
        result: ResultKind::None,
        charges: &[Base, Input("data")],
    },
    HostFunction {
        name: "secp256k1_recover",
        group: Crypto,
        params: &[
            p("hash", FixedBytes(32)),
            p("sig", FixedBytes(65)),
            p("out", Out(33)),
        ],
        result: ResultKind::Status(Secp256k1RecoverStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "secp256k1_verify",
        group: Crypto,
        params: &[
            p("hash", FixedBytes(32)),
            p("sig", FixedBytes(64)),
            p("key", FixedBytes(33)),
        ],
        result: ResultKind::Bool,
        charges: &[Base],
    },
    HostFunction {
        name: "secp256r1_verify",
        group: Crypto,
        params: &[
            p("hash", FixedBytes(32)),
            p("sig", FixedBytes(64)),
            p("key", FixedBytes(33)),
        ],
        result: ResultKind::Bool,
        charges: &[Base],
    },
    HostFunction {
        name: "secp256k1_decompress",
        group: Crypto,
        params: &[p("key", FixedBytes(33)), p("out", Out(65))],
        result: ResultKind::Status(Secp256k1DecompressStatus::CODES),
        charges: &[Base],
    },
    HostFunction {
        name: "ed25519_verify",
        group: Crypto,
        params: &[
            p("msg", Bytes),
            p("sig", FixedBytes(64)),
            p("key", FixedBytes(32)),
        ],
        result: ResultKind::Bool,
        charges: &[Base, Input("msg")],
    },
];
