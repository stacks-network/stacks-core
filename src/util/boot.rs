use std::convert::TryFrom;

use types::chainstate::StacksAddress;
use vm::types::QualifiedContractIdentifier;
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

#[cfg(test)]
pub fn boot_code_test_addr() -> StacksAddress {
    boot_code_addr(false)
}
