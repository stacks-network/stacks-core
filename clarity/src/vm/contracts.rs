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

use clarity_types::resident_bytes::ResidentBytes;
use stacks_common::types::StacksEpochId;

use crate::vm::ast::ContractAST;
use crate::vm::contexts::{ContractContext, GlobalContext};
use crate::vm::errors::VmExecutionError;
use crate::vm::eval_all;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::version::ClarityVersion;

#[derive(Serialize, Deserialize)]
pub struct Contract {
    pub contract_context: ContractContext,
}

impl ResidentBytes for Contract {
    fn heap_bytes(&self) -> usize {
        self.contract_context.heap_bytes()
    }
}

// AARON: this is an increasingly useless wrapper around a ContractContext struct.
//          will probably be removed soon.
impl Contract {
    pub fn initialize_from_ast(
        contract_identifier: QualifiedContractIdentifier,
        contract: &ContractAST,
        sponsor: Option<PrincipalData>,
        global_context: &mut GlobalContext,
        version: ClarityVersion,
    ) -> Result<Contract, VmExecutionError> {
        let mut contract_context = ContractContext::new(contract_identifier, version);

        eval_all(
            &contract.expressions,
            &mut contract_context,
            global_context,
            sponsor,
        )?;

        Ok(Contract { contract_context })
    }

    pub fn canonicalize_types(&mut self, epoch: &StacksEpochId) -> Result<(), VmExecutionError> {
        self.contract_context.canonicalize_types(epoch)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use clarity_types::resident_bytes::ResidentBytes;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::StacksEpochId;

    use crate::vm::GlobalContext;
    use crate::vm::ast::build_ast;
    use crate::vm::contexts::ContractContext;
    use crate::vm::contracts::Contract;
    use crate::vm::costs::LimitedCostTracker;
    use crate::vm::database::MemoryBackingStore;
    use crate::vm::types::QualifiedContractIdentifier;
    use crate::vm::version::ClarityVersion;

    fn expected_contract_context_heap_bytes(contract: &Contract) -> usize {
        let contract_context = &contract.contract_context;

        // This is a bit rigid and will break if we change ContractContext's fields, but will catch
        // if we forget to include a field in the resident_bytes calculation.
        contract_context.contract_identifier.heap_bytes()
            + contract_context.variables.heap_bytes()
            + contract_context.functions.heap_bytes()
            + contract_context.defined_traits.heap_bytes()
            + contract_context.implemented_traits.heap_bytes()
            + contract_context.persisted_names.heap_bytes()
            + contract_context.meta_data_map.heap_bytes()
            + contract_context.meta_data_var.heap_bytes()
            + contract_context.meta_nft.heap_bytes()
            + contract_context.meta_ft.heap_bytes()
    }

    #[track_caller]
    fn assert_contract_bytes_match_context_fields(contract: &Contract) {
        let expected_heap = expected_contract_context_heap_bytes(contract);

        assert_eq!(contract.contract_context.heap_bytes(), expected_heap);
        assert_eq!(contract.heap_bytes(), expected_heap);
        assert_eq!(
            contract.resident_bytes(),
            size_of::<Contract>() + expected_heap
        );
    }

    #[track_caller]
    fn initialize_contract_with_store(
        marf: &mut MemoryBackingStore,
        source: &str,
        contract_name: &str,
    ) -> Contract {
        let version = ClarityVersion::Clarity2;
        let epoch = StacksEpochId::Epoch21;
        let contract_identifier = QualifiedContractIdentifier::local(contract_name).unwrap();
        let conn = marf.as_clarity_db();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            conn,
            LimitedCostTracker::new_free(),
            epoch,
        );
        let contract_ast = build_ast(&contract_identifier, source, &mut (), version, epoch)
            .expect("contract source should parse");

        global_context
            .execute(|g| {
                Contract::initialize_from_ast(contract_identifier, &contract_ast, None, g, version)
            })
            .expect("contract source should initialize")
    }

    fn initialize_contract(source: &str, contract_name: &str) -> Contract {
        let mut marf = MemoryBackingStore::new();
        initialize_contract_with_store(&mut marf, source, contract_name)
    }

    #[test]
    fn resident_bytes_matches_empty_contract_context() {
        let contract_identifier =
            QualifiedContractIdentifier::local("resident-bytes-empty").unwrap();
        let contract = Contract {
            contract_context: ContractContext::new(contract_identifier, ClarityVersion::Clarity2),
        };

        assert!(contract.contract_context.variables.is_empty());
        assert!(contract.contract_context.functions.is_empty());
        assert!(contract.contract_context.defined_traits.is_empty());
        assert!(contract.contract_context.implemented_traits.is_empty());
        assert!(contract.contract_context.persisted_names.is_empty());
        assert!(contract.contract_context.meta_data_map.is_empty());
        assert!(contract.contract_context.meta_data_var.is_empty());
        assert!(contract.contract_context.meta_nft.is_empty());
        assert!(contract.contract_context.meta_ft.is_empty());

        assert_contract_bytes_match_context_fields(&contract);
        assert_eq!(
            contract.heap_bytes(),
            contract.contract_context.contract_identifier.heap_bytes()
        );
    }

    #[test]
    fn resident_bytes_covers_all_fields_in_rich_contract() {
        let contract = initialize_contract(
            r#"
            (define-data-var counter uint u0)
            (define-map balances { owner: principal } { amount: uint, memo: (string-ascii 32) })
            (define-constant label "resident-bytes")

            (define-private (helper (amount uint))
              (begin
                (var-set counter (+ (var-get counter) amount))
                (ok (var-get counter))))

            (define-read-only (lookup (owner principal))
              (default-to { amount: u0, memo: "none" }
                (map-get? balances { owner: owner })))

            (define-public (store (owner principal) (amount uint))
              (begin
                (map-set balances { owner: owner } { amount: amount, memo: "cache-entry" })
                (try! (helper amount))
                (ok true)))
            "#,
            "resident-bytes-rich",
        );

        assert_eq!(contract.contract_context.variables.len(), 1);
        assert_eq!(contract.contract_context.functions.len(), 3);
        assert_eq!(contract.contract_context.meta_data_map.len(), 1);
        assert_eq!(contract.contract_context.meta_data_var.len(), 1);
        assert!(contract.contract_context.persisted_names.len() >= 2);

        assert_contract_bytes_match_context_fields(&contract);

        // Magnitude check: a contract with 3 functions, a map, a var, and a constant
        // must have substantial heap allocation beyond the bare struct size.
        assert!(
            contract.resident_bytes() > size_of::<Contract>() + 1000,
            "rich contract resident_bytes ({}) should exceed struct size + 1000",
            contract.resident_bytes()
        );
    }

    #[test]
    fn resident_bytes_counts_ft_nft_and_traits() {
        let contract = initialize_contract(
            r#"
            (define-fungible-token gold)
            (define-fungible-token silver u1000000)
            (define-non-fungible-token deed uint)
            (define-non-fungible-token badge { class: uint, level: uint })
            (define-trait transferable (
                (transfer (uint principal principal) (response bool uint))
                (get-balance (principal) (response uint uint))))
            "#,
            "resident-bytes-ft-nft-trait",
        );

        assert_eq!(contract.contract_context.meta_ft.len(), 2);
        assert_eq!(contract.contract_context.meta_nft.len(), 2);
        assert_eq!(contract.contract_context.defined_traits.len(), 1);

        assert_contract_bytes_match_context_fields(&contract);

        // meta_nft contains a tuple key type (badge) — verify it contributes heap bytes
        let nft_heap: usize = contract
            .contract_context
            .meta_nft
            .values()
            .map(|m| m.heap_bytes())
            .sum();
        assert!(
            nft_heap > 0,
            "NFT metadata with tuple key type should have non-zero heap bytes"
        );

        // defined_traits contains function signatures — verify they contribute heap bytes
        let trait_heap: usize = contract
            .contract_context
            .defined_traits
            .values()
            .map(|m| m.heap_bytes())
            .sum();
        assert!(
            trait_heap > 0,
            "defined traits with function signatures should have non-zero heap bytes"
        );
    }

    #[test]
    fn resident_bytes_counts_implemented_traits() {
        let mut marf = MemoryBackingStore::new();

        // First contract defines the trait
        let _trait_contract = initialize_contract_with_store(
            &mut marf,
            r#"
            (define-trait transferable (
                (transfer (uint principal principal) (response bool uint))))
            "#,
            "trait-definer",
        );

        // Second contract implements the trait (requires the first to be deployed)
        let impl_contract = initialize_contract_with_store(
            &mut marf,
            r#"
            (impl-trait .trait-definer.transferable)
            (define-public (transfer (id uint) (from principal) (to principal))
              (ok true))
            "#,
            "trait-impl",
        );

        assert_eq!(impl_contract.contract_context.implemented_traits.len(), 1);

        assert_contract_bytes_match_context_fields(&impl_contract);

        // implemented_traits contains a TraitIdentifier; verify non-zero heap
        let impl_heap = impl_contract
            .contract_context
            .implemented_traits
            .heap_bytes();
        assert!(
            impl_heap > 0,
            "implemented_traits with a TraitIdentifier should have non-zero heap bytes"
        );
    }

    #[test]
    fn resident_bytes_grows_with_additional_initialized_content() {
        let single_function = initialize_contract(
            r#"
            (define-public (echo (value uint))
              (ok value))
            "#,
            "resident-bytes-single-fn",
        );
        let many_functions = initialize_contract(
            r#"
            (define-private (double (value uint)) (+ value value))
            (define-private (triple (value uint)) (+ value (+ value value)))
            (define-read-only (project (value uint))
              { original: value, doubled: (double value), tripled: (triple value) })
            (define-public (accumulate (a uint) (b uint) (c uint))
              (let (
                    (first (double a))
                    (second (triple b))
                    (third (+ c u7)))
                (ok (+ first (+ second third)))))
            "#,
            "resident-bytes-many-fns",
        );

        assert_contract_bytes_match_context_fields(&single_function);
        assert_contract_bytes_match_context_fields(&many_functions);
        assert!(
            many_functions.contract_context.functions.len()
                > single_function.contract_context.functions.len()
        );
        assert!(many_functions.heap_bytes() > single_function.heap_bytes());
        assert!(many_functions.resident_bytes() > single_function.resident_bytes());
    }
}
