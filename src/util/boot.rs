use std::convert::TryFrom;

use chainstate::stacks::db::StacksAccount;
use chainstate::stacks::{
    SinglesigHashMode, SinglesigSpendingCondition, TransactionAuth, TransactionPublicKeyEncoding,
    TransactionSpendingCondition,
};
use types::chainstate::StacksAddress;
use util::secp256k1::MessageSignature;
use vm::database::STXBalance;
use vm::types::{PrincipalData, QualifiedContractIdentifier};
use vm::ContractName;

pub fn boot_code_id(name: &str, mainnet: bool) -> QualifiedContractIdentifier {
    let addr = boot_code_addr(mainnet);
    QualifiedContractIdentifier::new(
        addr.into(),
        ContractName::try_from(name.to_string()).unwrap(),
    )
}

pub fn boot_code_addr(mainnet: bool) -> StacksAddress {
    StacksAddress::burn_address(mainnet)
}

pub fn boot_code_tx_auth(boot_code_address: StacksAddress) -> TransactionAuth {
    TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(
        SinglesigSpendingCondition {
            signer: boot_code_address.bytes.clone(),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
            nonce: 0,
            tx_fee: 0,
            signature: MessageSignature::empty(),
        },
    ))
}

pub fn boot_code_acc(boot_code_address: StacksAddress, boot_code_nonce: u64) -> StacksAccount {
    StacksAccount {
        principal: PrincipalData::Standard(boot_code_address.into()),
        nonce: boot_code_nonce,
        stx_balance: STXBalance::zero(),
    }
}

#[cfg(test)]
pub fn boot_code_test_addr() -> StacksAddress {
    boot_code_addr(false)
}
