use clarity::vm::database::STXBalance;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::ContractName;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::secp256k1::MessageSignature;

use crate::chainstate::stacks::db::StacksAccount;
use crate::chainstate::stacks::{
    SinglesigHashMode, SinglesigSpendingCondition, TransactionAuth, TransactionPublicKeyEncoding,
    TransactionSpendingCondition,
};

/// Returns the `QualifiedContractIdentifier` for the boot code contract.
///
/// # Panics
///
/// Panics if the contract name cannot be converted to `ContractName`.
pub fn boot_code_id(name: &str, mainnet: bool) -> QualifiedContractIdentifier {
    let addr = boot_code_addr(mainnet);
    QualifiedContractIdentifier::new(
        addr.into(),
        ContractName::try_from(name.to_string()).unwrap(),
    )
}

/// Returns the `StacksAddress` for the boot code.
pub fn boot_code_addr(mainnet: bool) -> StacksAddress {
    StacksAddress::burn_address(mainnet)
}

/// Returns the `TransactionAuth` for the boot code.
pub fn boot_code_tx_auth(boot_code_address: StacksAddress) -> TransactionAuth {
    TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(
        SinglesigSpendingCondition {
            signer: boot_code_address.bytes().clone(),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
            nonce: 0,
            tx_fee: 0,
            signature: MessageSignature::empty(),
        },
    ))
}

/// Returns the `StacksAccount` for the boot code with a specified nonce.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_code_id() {
        let id_mainnet = boot_code_id("test-contract", true);
        assert_eq!(id_mainnet.name.as_str(), "test-contract");

        let id_testnet = boot_code_id("test-contract", false);
        assert_eq!(id_testnet.name.as_str(), "test-contract");
    }

    #[test]
    #[should_panic]
    fn test_boot_code_id_invalid_name() {
        // ContractName validation rules will cause this to panic (cannot contain spaces)
        boot_code_id("invalid name", true);
    }

    #[test]
    fn test_boot_code_addr() {
        let addr_mainnet = boot_code_addr(true);
        let addr_testnet = boot_code_addr(false);
        assert_ne!(addr_mainnet, addr_testnet);
    }

    #[test]
    fn test_boot_code_acc() {
        let addr = boot_code_addr(false);
        let acc = boot_code_acc(addr.clone(), 10);
        assert_eq!(acc.nonce, 10);
        if let PrincipalData::Standard(p_addr) = acc.principal {
            assert_eq!(p_addr, addr.into());
        } else {
            panic!("Expected Standard principal");
        }
    }
}
