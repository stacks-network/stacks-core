// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
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

pub mod serialization;
pub mod signatures;

use std::str;

pub use clarity_types::types::{
    byte_len_of_serialization, ASCIIData, BuffData, CallableData, CharType, ContractIdentifier,
    ListData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    SequencedValue, StacksAddressExtensions, TraitIdentifier, TupleData, UTF8Data, Value,
    BOUND_VALUE_SERIALIZATION_BYTES, BOUND_VALUE_SERIALIZATION_HEX, MAX_TYPE_DEPTH, MAX_VALUE_SIZE,
    NONE, WRAPPER_VALUE_SIZE,
};

pub use self::std_principals::StandardPrincipalData;
use crate::vm::errors::CheckErrors;
pub use crate::vm::types::signatures::{
    parse_name_type_pairs, AssetIdentifier, BufferLength, FixedFunction, FunctionArg,
    FunctionSignature, FunctionType, ListTypeData, SequenceSubtype, StringSubtype,
    StringUTF8Length, TupleTypeSignature, TypeSignature, TypeSignatureExt, BUFF_20, BUFF_32,
    BUFF_33, BUFF_64, BUFF_65,
};
use crate::vm::ClarityVersion;

mod std_principals {
    pub use clarity_types::types::StandardPrincipalData;
}

// Properties for "get-block-info".
define_versioned_named_enum!(BlockInfoProperty(ClarityVersion) {
    Time("time", ClarityVersion::Clarity1),
    VrfSeed("vrf-seed", ClarityVersion::Clarity1),
    HeaderHash("header-hash", ClarityVersion::Clarity1),
    IdentityHeaderHash("id-header-hash", ClarityVersion::Clarity1),
    BurnchainHeaderHash("burnchain-header-hash", ClarityVersion::Clarity1),
    MinerAddress("miner-address", ClarityVersion::Clarity1),
    MinerSpendWinner("miner-spend-winner", ClarityVersion::Clarity2),
    MinerSpendTotal("miner-spend-total", ClarityVersion::Clarity2),
    BlockReward("block-reward", ClarityVersion::Clarity2),
});

// Properties for "get-burn-block-info".
define_named_enum!(BurnBlockInfoProperty {
    HeaderHash("header-hash"),
    PoxAddrs("pox-addrs"),
});

define_named_enum!(StacksBlockInfoProperty {
    IndexHeaderHash("id-header-hash"),
    HeaderHash("header-hash"),
    Time("time"),
});

define_named_enum!(TenureInfoProperty {
    Time("time"),
    VrfSeed("vrf-seed"),
    BurnchainHeaderHash("burnchain-header-hash"),
    MinerAddress("miner-address"),
    MinerSpendWinner("miner-spend-winner"),
    MinerSpendTotal("miner-spend-total"),
    BlockReward("block-reward"),
});

impl BlockInfoProperty {
    pub fn type_result(&self) -> TypeSignature {
        use self::BlockInfoProperty::*;
        match self {
            Time | MinerSpendWinner | MinerSpendTotal | BlockReward => TypeSignature::UIntType,
            IdentityHeaderHash | VrfSeed | HeaderHash | BurnchainHeaderHash => BUFF_32.clone(),
            MinerAddress => TypeSignature::PrincipalType,
        }
    }
}

impl BurnBlockInfoProperty {
    pub fn type_result(&self) -> std::result::Result<TypeSignature, CheckErrors> {
        use self::BurnBlockInfoProperty::*;
        let result = match self {
            HeaderHash => BUFF_32.clone(),
            PoxAddrs => TupleTypeSignature::try_from(vec![
                (
                    "addrs".into(),
                    TypeSignature::list_of(
                        TypeSignature::TupleType(
                            TupleTypeSignature::try_from(vec![
                                ("version".into(), TypeSignature::BUFFER_1),
                                ("hashbytes".into(), BUFF_32.clone()),
                            ])
                            .map_err(|_| {
                                CheckErrors::Expects(
                                    "FATAL: bad type signature for pox addr".into(),
                                )
                            })?,
                        ),
                        2,
                    )
                    .map_err(|_| CheckErrors::Expects("FATAL: bad list type signature".into()))?,
                ),
                ("payout".into(), TypeSignature::UIntType),
            ])
            .map_err(|_| CheckErrors::Expects("FATAL: bad type signature for pox addr".into()))?
            .into(),
        };
        Ok(result)
    }
}

impl StacksBlockInfoProperty {
    pub fn type_result(&self) -> TypeSignature {
        use self::StacksBlockInfoProperty::*;
        match self {
            Time => TypeSignature::UIntType,
            IndexHeaderHash | HeaderHash => BUFF_32.clone(),
        }
    }
}

impl TenureInfoProperty {
    pub fn type_result(&self) -> TypeSignature {
        use self::TenureInfoProperty::*;
        match self {
            Time | MinerSpendWinner | MinerSpendTotal | BlockReward => TypeSignature::UIntType,
            VrfSeed | BurnchainHeaderHash => BUFF_32.clone(),
            MinerAddress => TypeSignature::PrincipalType,
        }
    }
}
