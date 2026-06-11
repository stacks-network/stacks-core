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

use blockstack_lib::chainstate::stacks::{TransactionPayload, TransactionPayloadID};

use crate::db::app::models::StacksTxType;

fn tx_type_display_name(id: TransactionPayloadID) -> &'static str {
    use TransactionPayloadID::*;
    match id {
        TokenTransfer => "Token Transfer",
        SmartContract => "Contract Deploy",
        VersionedSmartContract => "Contract Deploy (Versioned)",
        ContractCall => "Contract Call",
        PoisonMicroblock => "Poison Microblock",
        Coinbase => "Coinbase",
        CoinbaseToAltRecipient => "Coinbase (Alt. Recipient)",
        NakamotoCoinbase => "Coinbase (Nakamoto)",
        TenureChange => "Tenure Change",
    }
}

pub fn resolve_tx_type(payload: &TransactionPayload) -> StacksTxType {
    let id = match payload {
        TransactionPayload::TokenTransfer(..) => TransactionPayloadID::TokenTransfer,
        TransactionPayload::SmartContract(_, Some(_)) => {
            TransactionPayloadID::VersionedSmartContract
        }
        TransactionPayload::SmartContract(_, None) => TransactionPayloadID::SmartContract,
        TransactionPayload::ContractCall(..) => TransactionPayloadID::ContractCall,
        TransactionPayload::PoisonMicroblock(..) => TransactionPayloadID::PoisonMicroblock,
        TransactionPayload::Coinbase(_, _, Some(_)) => TransactionPayloadID::NakamotoCoinbase,
        TransactionPayload::Coinbase(_, Some(_), None) => {
            TransactionPayloadID::CoinbaseToAltRecipient
        }
        TransactionPayload::Coinbase(_, None, None) => TransactionPayloadID::Coinbase,
        TransactionPayload::TenureChange(..) => TransactionPayloadID::TenureChange,
    };
    StacksTxType {
        id: id as i32,
        name: tx_type_display_name(id).to_string(),
    }
}
