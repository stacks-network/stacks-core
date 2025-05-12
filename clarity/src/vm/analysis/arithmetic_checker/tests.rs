// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
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

#[cfg(test)]
use rstest::rstest;
#[cfg(test)]
use rstest_reuse::{self, *};
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::arithmetic_checker::Error::*;
use crate::vm::analysis::arithmetic_checker::{ArithmeticOnlyChecker, Error};
use crate::vm::analysis::ContractAnalysis;
use crate::vm::ast::parse;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::functions::define::DefineFunctions;
use crate::vm::functions::NativeFunctions;
use crate::vm::tests::test_clarity_versions;
use crate::vm::tooling::mem_type_check;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::variables::NativeVariables;
use crate::vm::ClarityVersion;

/// Checks whether or not a contract only contains arithmetic expressions (for example, defining a
/// map would not pass this check).
/// This check is useful in determining the validity of new potential cost functions.
fn arithmetic_check(
    contract: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<(), Error> {
    let contract_identifier = QualifiedContractIdentifier::transient();
    let expressions = parse(&contract_identifier, contract, version, epoch).unwrap();

    let analysis = ContractAnalysis::new(
        contract_identifier,
        expressions,
        LimitedCostTracker::new_free(),
        epoch,
        version,
    );

    ArithmeticOnlyChecker::run(&analysis)
}

fn check_good(contract: &str, version: ClarityVersion, epoch: StacksEpochId) {
    let analysis = mem_type_check(contract, version, epoch).unwrap().1;
    ArithmeticOnlyChecker::run(&analysis).expect("Should pass arithmetic checks");
}

#[apply(test_clarity_versions)]
fn test_bad_defines(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let tests = [
        ("(define-public (foo) (ok 1))", DefineTypeForbidden(DefineFunctions::PublicFunction)),
        ("(define-map foo-map ((a uint)) ((b uint))) (define-private (foo) (map-get? foo-map {a: u1}))", DefineTypeForbidden(DefineFunctions::Map)),
        ("(define-data-var foo-var uint u1) (define-private (foo) (var-get foo-var))", DefineTypeForbidden(DefineFunctions::PersistedVariable)),
        ("(define-fungible-token tokaroos u500)", DefineTypeForbidden(DefineFunctions::FungibleToken)),
        ("(define-fungible-token tokaroos)", DefineTypeForbidden(DefineFunctions::FungibleToken)),
        ("(define-non-fungible-token tokaroos uint)", DefineTypeForbidden(DefineFunctions::NonFungibleToken)),
        ("(define-trait foo-trait ((foo (uint)) (response uint uint)))", DefineTypeForbidden(DefineFunctions::Trait)),
    ];

    // Check bad defines for each clarity version
    for (contract, error) in tests.iter() {
        assert_eq!(
            arithmetic_check(contract, version, epoch),
            Err(error.clone()),
            "Check contract:\n {}",
            contract
        );
    }
}

#[test]
fn test_variables_fail_arithmetic_check_clarity1() {
    // Tests the behavior using Clarity1.
    let tests = [
        (
            "(define-private (foo) burn-block-height)",
            Err(VariableForbidden(NativeVariables::BurnBlockHeight)),
        ),
        (
            "(define-private (foo) block-height)",
            Err(VariableForbidden(NativeVariables::BlockHeight)),
        ),
        (
            "(define-private (foo) tx-sender)",
            Err(VariableForbidden(NativeVariables::TxSender)),
        ),
        (
            "(define-private (foo) contract-caller)",
            Err(VariableForbidden(NativeVariables::ContractCaller)),
        ),
        (
            "(define-private (foo) is-in-regtest)",
            Err(VariableForbidden(NativeVariables::Regtest)),
        ),
        (
            "(define-private (foo) stx-liquid-supply)",
            Err(VariableForbidden(NativeVariables::TotalLiquidMicroSTX)),
        ),
        ("(define-private (foo) tx-sponsor?)", Ok(())),
        ("(define-private (foo) is-in-mainnet)", Ok(())),
        ("(define-private (foo) chain-id)", Ok(())),
    ];

    for (contract, result) in tests.iter() {
        assert_eq!(
            arithmetic_check(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch2_05),
            result.clone(),
            "Check contract:\n {}",
            contract
        );
        assert_eq!(
            arithmetic_check(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch21),
            result.clone(),
            "Check contract:\n {}",
            contract
        );
    }

    let tests = [
        "(define-private (foo) (begin true false none))",
        "(define-private (foo) 1)",
    ];

    for contract in tests.iter() {
        check_good(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch2_05);
        check_good(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch21);
    }
}

#[test]
fn test_variables_fail_arithmetic_check_clarity2() {
    // Tests the behavior using Clarity2.
    let tests = [
        (
            "(define-private (foo) burn-block-height)",
            Err(VariableForbidden(NativeVariables::BurnBlockHeight)),
        ),
        (
            "(define-private (foo) block-height)",
            Err(VariableForbidden(NativeVariables::BlockHeight)),
        ),
        (
            "(define-private (foo) tx-sender)",
            Err(VariableForbidden(NativeVariables::TxSender)),
        ),
        (
            "(define-private (foo) contract-caller)",
            Err(VariableForbidden(NativeVariables::ContractCaller)),
        ),
        (
            "(define-private (foo) is-in-regtest)",
            Err(VariableForbidden(NativeVariables::Regtest)),
        ),
        (
            "(define-private (foo) stx-liquid-supply)",
            Err(VariableForbidden(NativeVariables::TotalLiquidMicroSTX)),
        ),
        (
            "(define-private (foo) tx-sponsor?)",
            Err(VariableForbidden(NativeVariables::TxSponsor)),
        ),
        (
            "(define-private (foo) is-in-mainnet)",
            Err(VariableForbidden(NativeVariables::Mainnet)),
        ),
        (
            "(define-private (foo) chain-id)",
            Err(VariableForbidden(NativeVariables::ChainId)),
        ),
    ];

    for (contract, result) in tests.iter() {
        assert_eq!(
            arithmetic_check(contract, ClarityVersion::Clarity2, StacksEpochId::Epoch21),
            result.clone(),
            "Check contract:\n {}",
            contract
        );
    }
}

#[test]
fn test_functions_clarity1() {
    // Tests all functions against Clarity1 VM. Results should be different for Clarity1 vs Clarity2 functions.
    let tests = [
        // Clarity1 functions.
        ("(define-private (foo) (at-block 0x0202020202020202020202020202020202020202020202020202020202020202 (+ 1 2)))",
         Err(FunctionNotPermitted(NativeFunctions::AtBlock))),
        ("(define-private (foo) (map-get? foo-map {a: u1}))",
         Err(FunctionNotPermitted(NativeFunctions::FetchEntry))),
        ("(define-private (foo) (map-delete foo-map {a: u1}))",
         Err(FunctionNotPermitted(NativeFunctions::DeleteEntry))),
        ("(define-private (foo) (map-set foo-map {a: u1} {b: u2}))",
         Err(FunctionNotPermitted(NativeFunctions::SetEntry))),
        ("(define-private (foo) (map-insert foo-map {a: u1} {b: u2}))",
         Err(FunctionNotPermitted(NativeFunctions::InsertEntry))),
        ("(define-private (foo) (var-get foo-var))",
         Err(FunctionNotPermitted(NativeFunctions::FetchVar))),
        ("(define-private (foo) (var-set foo-var u2))",
         Err(FunctionNotPermitted(NativeFunctions::SetVar))),
        ("(define-private (foo (a principal)) (ft-get-balance tokaroos a))",
         Err(FunctionNotPermitted(NativeFunctions::GetTokenBalance))),
        ("(define-private (foo (a principal)) 
          (ft-transfer? stackaroo u50 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF))",
         Err(FunctionNotPermitted(NativeFunctions::TransferToken))),
        ("(define-private (foo (a principal)) 
          (ft-mint? stackaroo u100 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR))",
         Err(FunctionNotPermitted(NativeFunctions::MintToken))),
        ("(define-private (foo (a principal)) 
           (nft-mint? stackaroo \"Roo\" 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR))",
         Err(FunctionNotPermitted(NativeFunctions::MintAsset))),
        ("(nft-transfer? stackaroo \"Roo\" 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF)",
         Err(FunctionNotPermitted(NativeFunctions::TransferAsset))),
        ("(nft-get-owner? stackaroo \"Roo\")",
         Err(FunctionNotPermitted(NativeFunctions::GetAssetOwner))),
        ("(get-block-info? id-header-hash 0)",
         Err(FunctionNotPermitted(NativeFunctions::GetBlockInfo))),
        ("(define-private (foo) (contract-call? .bar outer-call))",
         Err(FunctionNotPermitted(NativeFunctions::ContractCall))),
        ("(stx-get-balance 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF)",
         Err(FunctionNotPermitted(NativeFunctions::GetStxBalance))),
        ("(stx-burn? u100 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF)",
         Err(FunctionNotPermitted(NativeFunctions::StxBurn))),
        (r#"(stx-transfer? u100 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF)"#,
         Err(FunctionNotPermitted(NativeFunctions::StxTransfer))),
        ("(define-private (foo (a (list 3 uint)))
           (map log2 a))",
         Err(FunctionNotPermitted(NativeFunctions::Map))),
        ("(define-private (foo (a (list 3 (optional uint))))
           (filter is-none a))",
         Err(FunctionNotPermitted(NativeFunctions::Filter))),
        ("(define-private (foo (a (list 3 uint)))
           (append a u4))",
         Err(FunctionNotPermitted(NativeFunctions::Append))),
        ("(define-private (foo (a (list 3 uint)))
           (concat a a))",
         Err(FunctionNotPermitted(NativeFunctions::Concat))),
        ("(define-private (foo (a (list 3 uint)))
           (as-max-len? a u4))",
         Err(FunctionNotPermitted(NativeFunctions::AsMaxLen))),
        ("(define-private (foo) (print 10))",
         Err(FunctionNotPermitted(NativeFunctions::Print))),
        ("(define-private (foo) (list 3 4 10))",
         Err(FunctionNotPermitted(NativeFunctions::ListCons))),
        ("(define-private (foo) (keccak256 0))",
         Err(FunctionNotPermitted(NativeFunctions::Keccak256))),
        ("(define-private (foo) (hash160 0))",
         Err(FunctionNotPermitted(NativeFunctions::Hash160))),
        ("(define-private (foo) (secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04  0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301))",
         Err(FunctionNotPermitted(NativeFunctions::Secp256k1Recover))),
        ("(define-private (foo) (secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04
 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a13
 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110))",
         Err(FunctionNotPermitted(NativeFunctions::Secp256k1Verify))),
        ("(define-private (foo) (sha256 0))",
         Err(FunctionNotPermitted(NativeFunctions::Sha256))),
        ("(define-private (foo) (sha512 0))",
         Err(FunctionNotPermitted(NativeFunctions::Sha512))),
        ("(define-private (foo) (sha512/256 0))",
         Err(FunctionNotPermitted(NativeFunctions::Sha512Trunc256))),

        // Clarity2 functions.
        (r#"(stx-transfer-memo? u100 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 0x010203)"#,
         Ok(())),
        ("(define-private (foo (a (list 3 uint)))
         (slice? a u2 u3))",
         Ok(())),
        ("(define-private (foo (a (list 3 uint)) (b uint))
         (replace-at? a u1 b))",
          Ok(())),
        ("(buff-to-int-le 0x0001)",
         Ok(())),
        ("(buff-to-uint-le 0x0001)",
         Ok(())),
        ("(buff-to-int-be 0x0001)",
         Ok(())),
        ("(buff-to-uint-be 0x0001)",
         Ok(())),
        ("(buff-to-uint-be 0x0001)",
         Ok(())),
        ("(is-standard 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)", 
         Ok(())),
        ("(principal-destruct? 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)",
         Ok(())),
        ("(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320)",
         Ok(())),
        ("(string-to-int? \"-1\")",
         Ok(())),
        ("(string-to-uint? \"1\")",
         Ok(())),
        ("(int-to-ascii 5)",
         Ok(())),
        ("(int-to-utf8 10)",
         Ok(())),
        ("(get-burn-block-info? header-hash u0)",
         Ok(())),
        ("(stx-account 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
         Ok(())),
        ("(to-consensus-buff? 3)",
         Ok(())),
        ("(from-consensus-buff? true 0x03)",
         Ok(())),
    ];

    for (contract, result) in tests.iter() {
        assert_eq!(
            arithmetic_check(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch2_05),
            result.clone(),
            "Check contract:\n {}",
            contract
        );
        assert_eq!(
            arithmetic_check(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch21),
            result.clone(),
            "Check contract:\n {}",
            contract
        );
    }
}

#[test]
fn test_functions_clarity2() {
    // Tests functions against Clarity2 VM. The Clarity1 functions should still cause an error.
    let tests = [
        // Clarity2 functions.
        (r#"(stx-transfer-memo? u100 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 0x010203)"#,
        Err(FunctionNotPermitted(NativeFunctions::StxTransferMemo))),
        ("(define-private (foo (a (list 3 uint)))
              (slice? a u2 u3))",
         Err(FunctionNotPermitted(NativeFunctions::Slice))),
        ("(define-private (foo (a (list 3 uint)))
              (replace-at? a u2 (list u3)))",
         Err(FunctionNotPermitted(NativeFunctions::ReplaceAt))),
        ("(buff-to-int-le 0x0001)",
         Err(FunctionNotPermitted(NativeFunctions::BuffToIntLe))),
        ("(buff-to-uint-le 0x0001)",
         Err(FunctionNotPermitted(NativeFunctions::BuffToUIntLe))),
        ("(buff-to-int-be 0x0001)",
         Err(FunctionNotPermitted(NativeFunctions::BuffToIntBe))),
        ("(buff-to-uint-be 0x0001)",
         Err(FunctionNotPermitted(NativeFunctions::BuffToUIntBe))),
        ("(is-standard 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)",
         Err(FunctionNotPermitted(NativeFunctions::IsStandard))),
        ("(principal-destruct? 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)",
         Err(FunctionNotPermitted(NativeFunctions::PrincipalDestruct))),
        ("(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320)", 
         Err(FunctionNotPermitted(NativeFunctions::PrincipalConstruct))),
        ("(string-to-int? \"-1\")",
         Err(FunctionNotPermitted(NativeFunctions::StringToInt))),
        ("(string-to-uint? \"1\")",
         Err(FunctionNotPermitted(NativeFunctions::StringToUInt))),
        ("(int-to-ascii 5)",
         Err(FunctionNotPermitted(NativeFunctions::IntToAscii))),
        ("(int-to-utf8 10)",
         Err(FunctionNotPermitted(NativeFunctions::IntToUtf8))),
        ("(get-burn-block-info? header-hash u0)",
         Err(FunctionNotPermitted(NativeFunctions::GetBurnBlockInfo))),
        ("(stx-account 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
         Err(FunctionNotPermitted(NativeFunctions::StxGetAccount))),
        ("(to-consensus-buff? 3)",
         Err(FunctionNotPermitted(NativeFunctions::ToConsensusBuff))),
        ("(from-consensus-buff? true 0x03)",
         Err(FunctionNotPermitted(NativeFunctions::FromConsensusBuff))),

        // Clarity1 functions.
        ("(define-private (foo) (at-block 0x0202020202020202020202020202020202020202020202020202020202020202 (+ 1 2)))",
         Err(FunctionNotPermitted(NativeFunctions::AtBlock))),
        ("(define-private (foo) (map-get? foo-map {a: u1}))",
         Err(FunctionNotPermitted(NativeFunctions::FetchEntry))),
        ("(define-private (foo) (map-delete foo-map {a: u1}))",
         Err(FunctionNotPermitted(NativeFunctions::DeleteEntry))),
        ("(define-private (foo) (map-set foo-map {a: u1} {b: u2}))",
         Err(FunctionNotPermitted(NativeFunctions::SetEntry))),
        ("(define-private (foo) (map-insert foo-map {a: u1} {b: u2}))",
         Err(FunctionNotPermitted(NativeFunctions::InsertEntry))),
        ("(define-private (foo) (var-get foo-var))",
         Err(FunctionNotPermitted(NativeFunctions::FetchVar))),
        ("(define-private (foo) (var-set foo-var u2))",
         Err(FunctionNotPermitted(NativeFunctions::SetVar))),
        ("(define-private (foo (a principal)) (ft-get-balance tokaroos a))",
         Err(FunctionNotPermitted(NativeFunctions::GetTokenBalance))),
        ("(define-private (foo (a principal))
          (ft-transfer? stackaroo u50 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF))",
         Err(FunctionNotPermitted(NativeFunctions::TransferToken))),
        ("(define-private (foo (a principal))
          (ft-mint? stackaroo u100 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR))",
         Err(FunctionNotPermitted(NativeFunctions::MintToken))),
        ("(define-private (foo (a principal))
           (nft-mint? stackaroo \"Roo\" 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR))",
         Err(FunctionNotPermitted(NativeFunctions::MintAsset))),
        ("(nft-transfer? stackaroo \"Roo\" 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF)",
         Err(FunctionNotPermitted(NativeFunctions::TransferAsset))),
        ("(nft-get-owner? stackaroo \"Roo\")",
         Err(FunctionNotPermitted(NativeFunctions::GetAssetOwner))),
        ("(get-block-info? id-header-hash 0)",
         Err(FunctionNotPermitted(NativeFunctions::GetBlockInfo))),
        ("(define-private (foo) (contract-call? .bar outer-call))",
         Err(FunctionNotPermitted(NativeFunctions::ContractCall))),
        ("(stx-get-balance 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF)",
         Err(FunctionNotPermitted(NativeFunctions::GetStxBalance))),
        ("(stx-burn? u100 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF)",
         Err(FunctionNotPermitted(NativeFunctions::StxBurn))),
        (r#"(stx-transfer? u100 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF)"#,
         Err(FunctionNotPermitted(NativeFunctions::StxTransfer))),
        ("(define-private (foo (a (list 3 uint)))
           (map log2 a))",
         Err(FunctionNotPermitted(NativeFunctions::Map))),
        ("(define-private (foo (a (list 3 (optional uint))))
           (filter is-none a))",
         Err(FunctionNotPermitted(NativeFunctions::Filter))),
        ("(define-private (foo (a (list 3 uint)))
           (append a u4))",
         Err(FunctionNotPermitted(NativeFunctions::Append))),
        ("(define-private (foo (a (list 3 uint)))
           (concat a a))",
         Err(FunctionNotPermitted(NativeFunctions::Concat))),
        ("(define-private (foo (a (list 3 uint)))
           (as-max-len? a u4))",
         Err(FunctionNotPermitted(NativeFunctions::AsMaxLen))),
        ("(define-private (foo) (print 10))",
         Err(FunctionNotPermitted(NativeFunctions::Print))),
        ("(define-private (foo) (list 3 4 10))",
         Err(FunctionNotPermitted(NativeFunctions::ListCons))),
        ("(define-private (foo) (keccak256 0))",
         Err(FunctionNotPermitted(NativeFunctions::Keccak256))),
        ("(define-private (foo) (hash160 0))",
         Err(FunctionNotPermitted(NativeFunctions::Hash160))),
        ("(define-private (foo) (secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04  0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301))",
         Err(FunctionNotPermitted(NativeFunctions::Secp256k1Recover))),
        ("(define-private (foo) (secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04
 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a13
 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110))",
         Err(FunctionNotPermitted(NativeFunctions::Secp256k1Verify))),
        ("(define-private (foo) (sha256 0))",
         Err(FunctionNotPermitted(NativeFunctions::Sha256))),
        ("(define-private (foo) (sha512 0))",
         Err(FunctionNotPermitted(NativeFunctions::Sha512))),
        ("(define-private (foo) (sha512/256 0))",
         Err(FunctionNotPermitted(NativeFunctions::Sha512Trunc256))),
    ];

    for (contract, result) in tests.iter() {
        assert_eq!(
            arithmetic_check(contract, ClarityVersion::Clarity2, StacksEpochId::Epoch21),
            result.clone(),
            "Check contract:\n {}",
            contract
        );
    }
}

#[test]
fn test_functions_contract() {
    let good_tests = [
        "(match (if (is-eq 0 1) (ok 1) (err 2))
            ok-val (+ 1 ok-val)
            err-val (+ 2 err-val))",
        "(match (if (is-eq 0 1) (some 1) none)
            ok-val (+ 1 ok-val)
            2)",
        "(get a { a: (+ 9 1), b: (if (> 2 3) (* 4 4) (/ 4 2)) })",
        "(define-private (foo)
           (let ((a (+ 3 2 3))) (log2 a)))",
        "(define-private (foo)
           (let ((a (+ 32 3 4)) (b (- 32 1))
                 (c (if (and (< 3 2) (<= 3 2) (>= 4 5) (or (is-eq (mod 5 4) 0) (not (> 3 2))))
                    (pow u2 (log2 (sqrti u100000)))
                    (xor u120 u280)))
                 (d (default-to u0 (some u2))))
             (begin (unwrap! (some u3) u1)
                    (unwrap-err! (err u5) u4)
                    (asserts! true u4)
                    (unwrap-panic (some u3))
                    (unwrap-err-panic (err u5)))))",
        "(define-private (foo) (to-int (to-uint 34)))
         (define-private (bar) (foo))",
        "(define-private (foo) (begin
           (is-some (some 4))
           (is-none (some 4))
           (is-ok (ok 4))
           (is-err (ok 5))
           (try! (some 4))
           (some 5)))
         (define-read-only (bar) (foo))",
    ];

    for contract in good_tests.iter() {
        check_good(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch2_05);
        check_good(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch21);
        check_good(contract, ClarityVersion::Clarity2, StacksEpochId::Epoch21);
    }
}
