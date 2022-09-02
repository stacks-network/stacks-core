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

use assert_json_diff;
use serde_json;

use crate::vm::analysis::errors::CheckErrors;
use crate::vm::analysis::run_analysis;
use crate::vm::analysis::type_checker::tests::mem_type_check;
use crate::vm::analysis::{contract_interface_builder::build_contract_interface, AnalysisDatabase};
use crate::vm::ast::parse;
use crate::vm::database::MemoryBackingStore;
use crate::vm::types::{QualifiedContractIdentifier, TypeSignature};
use crate::vm::{
    analysis::{CheckError, ContractAnalysis},
    costs::LimitedCostTracker,
    ClarityVersion, SymbolicExpression,
};
use stacks_common::types::StacksEpochId;

#[template]
#[rstest]
#[case(ClarityVersion::Clarity1, StacksEpochId::Epoch2_05)]
#[case(ClarityVersion::Clarity1, StacksEpochId::Epoch21)]
#[case(ClarityVersion::Clarity2, StacksEpochId::Epoch21)]
fn test_clarity_versions_contracts(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {}

/// backwards-compatibility shim
pub fn type_check(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    analysis_db: &mut AnalysisDatabase,
    save_contract: bool,
) -> Result<ContractAnalysis, CheckError> {
    run_analysis(
        contract_identifier,
        expressions,
        analysis_db,
        save_contract,
        LimitedCostTracker::new_free(),
        ClarityVersion::Clarity2,
    )
    .map_err(|(e, _)| e)
}

const SIMPLE_TOKENS: &str = "(define-map tokens { account: principal } { balance: uint })
         (define-read-only (my-get-token-balance (account principal))
            (let ((balance
                  (get balance (map-get? tokens (tuple (account account))))))
              (default-to u0 balance)))

         (define-private (token-credit! (account principal) (amount uint))
            (if (<= amount u0)
                (err 1)
                (let ((current-amount (my-get-token-balance account)))
                  (begin
                    (map-set tokens (tuple (account account))
                                       (tuple (balance (+ amount current-amount))))
                    (ok u0)))))
         (define-public (token-transfer (to principal) (amount uint))
          (let ((balance (my-get-token-balance tx-sender)))
             (if (or (> amount balance) (<= amount u0))
                 (err 2)
                 (begin
                   (map-set tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))
         (begin (unwrap-panic (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR u10000))
                (unwrap-panic (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G u300)))";

const SIMPLE_NAMES: &str = "(define-constant burn-address 'SP000000000000000000002Q6VF78)
         (define-private (price-function (name uint))
           (if (< name u100000) u1000 u100))
         
         (define-map name-map 
           { name: uint } { owner: principal })
         (define-map preorder-map
           { name-hash: (buff 20) }
           { buyer: principal, paid: uint })

         (define-private (check-balance)
           (contract-call? .tokens my-get-token-balance tx-sender))

         (define-public (preorder 
                        (name-hash (buff 20))
                        (name-price uint))
           (let ((xfer-result (contract-call? .tokens token-transfer
                                  burn-address name-price)))
            (if (is-ok xfer-result)
               (if
                 (map-insert preorder-map
                   (tuple (name-hash name-hash))
                   (tuple (paid name-price)
                          (buyer tx-sender)))
                 (ok 0) (err 2))
               (if (is-eq (unwrap-err! xfer-result (err (- 1)))
                        2)
                   (err 1) (err 3)))))

         (define-public (register
                        (recipient-principal principal)
                        (name uint)
                        (salt uint))
           (let ((preorder-entry
                   ;; preorder entry must exist!
                   (unwrap! (map-get? preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 2)))
                 (name-entry 
                   (map-get? name-map (tuple (name name)))))
             (if (and
                  ;; name shouldn't *already* exist
                  (is-none name-entry)
                  ;; preorder must have paid enough
                  (<= (price-function name) 
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (is-eq tx-sender
                       (get buyer preorder-entry)))
                  (if (and
                    (map-insert name-map
                      (tuple (name name))
                      (tuple (owner recipient-principal)))
                    (map-delete preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                    (ok 0)
                    (err 3))
                  (err 4))))";

#[test]
fn test_names_tokens_contracts_interface() {
    const INTERFACE_TEST_CONTRACT: &str = "
        (define-constant var1 'SP000000000000000000002Q6VF78)
        (define-constant var2 true)
        (define-constant var3 45)

        (define-data-var d-var1 bool true)
        (define-data-var d-var2 int 2)
        (define-data-var d-var3 (buff 5) 0xdeadbeef)

        (define-map map1 { name: int } { owner: principal })
        (define-map map2 { k-name-1: bool } { v-name-1: (buff 33) })
        (define-map map3 { k-name-2: bool } { v-name-2: (tuple (n1 int) (n2 bool)) })

        (define-private (f00 (a1 int)) true)
        (define-private (f01 (a1 bool)) true)
        (define-private (f02 (a1 principal)) true)
        (define-private (f03 (a1 (buff 54))) true)
        (define-private (f04 (a1 (tuple (t-name1 bool) (t-name2 int)))) true)
        (define-private (f05 (a1 (list 7 (list 3 int)))) true)

        (define-private (f06) 1)
        (define-private (f07) true)
        (define-private (f08) 'SP000000000000000000002Q6VF78)
        (define-private (f09) 0xdeadbeef)
        (define-private (f10) (tuple (tn1 true) (tn2 0) (tn3 0xff) ))
        (define-private (f11) (map-get? map1 (tuple (name 0))))
        (define-private (f12) (ok 3))
        (define-private (f13) (err 6))
        (define-private (f14) (if true (ok 1) (err 2)))
        (define-private (f15) (list 1 2 3))
        (define-private (f16) (list (list (list 5)) (list (list 55))))

        (define-public (pub-f01) (ok 1))
        (define-public (pub-f02) (ok true))
        (define-public (pub-f03) (err true))
        (define-public (pub-f04) (if true (ok 1) (err 2)))
        (define-public (pub-f05 (a1 int)) (ok true))

        (define-read-only (ro-f01) 0)
        (define-read-only (ro-f02 (a1 int)) 0)
    ";

    let contract_analysis = mem_type_check(INTERFACE_TEST_CONTRACT).unwrap().1;
    let test_contract_json_str = build_contract_interface(&contract_analysis).serialize();
    let test_contract_json: serde_json::Value =
        serde_json::from_str(&test_contract_json_str).unwrap();

    let test_contract_json_expected: serde_json::Value = serde_json::from_str(r#"{
        "functions": [
            { "name": "f00",
                "access": "private",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": "bool" }
            },
            { "name": "f01",
                "access": "private",
                "args": [{ "name": "a1", "type": "bool" }],
                "outputs": { "type": "bool" }
            },
            { "name": "f02",
                "access": "private",
                "args": [{ "name": "a1", "type": "principal" }],
                "outputs": { "type": "bool" }
            },
            { "name": "f03",
                "access": "private",
                "args": [{ "name": "a1", "type": { "buffer": { "length": 54 } } }],
                "outputs": { "type": "bool" }
            },
            { "name": "f04",
                "access": "private",
                "args": [{ "name": "a1", "type": { "tuple": [
                    { "name": "t-name1", "type": "bool" },
                    { "name": "t-name2", "type": "int128" }
                ] } }],
                "outputs": { "type": "bool" }
            },
            { "name": "f05",
                "access": "private",
                "args": [{ "name": "a1", "type": { "list": { "type": { "list": { "type": "int128", "length": 3 } }, "length": 7 } } }],
                "outputs": { "type": "bool" }
            },
            { "name": "f06",
                "access": "private",
                "args": [],
                "outputs": { "type": "int128" }
            },
            { "name": "f07",
                "access": "private",
                "args": [],
                "outputs": { "type": "bool" }
            },
            { "name": "f08",
                "access": "private",
                "args": [],
                "outputs": { "type": "principal" }
            },
            { "name": "f09",
                "access": "private",
                "args": [],
                "outputs": { "type": { "buffer": { "length": 4 } } }
            },
            { "name": "f10",
                "access": "private",
                "args": [],
                "outputs": { "type": { "tuple": [
                    { "name": "tn1", "type": "bool" },
                    { "name": "tn2", "type": "int128" },
                    { "name": "tn3", "type": { "buffer": { "length": 1 } }}
                ] } } 
            },
            { "name": "f11",
                "access": "private",
                "args": [],
                "outputs": { "type": { "optional": { "tuple": [ {
                    "name": "owner",
                    "type": "principal"
                 } ] } } }
            },
            { "name": "f12",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "none" } } }
            },
            { "name": "f13",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "none", "error": "int128" } } }
            },
            { "name": "f14",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "int128" } } }
            },
            { "name": "f15",
                "access": "private",
                "args": [],
                "outputs": { "type": { "list": { "type": "int128", "length": 3 } } }
            },
            { "name": "f16",
                "access": "private",
                "args": [],
                "outputs": {
                  "type": { "list": {
                      "type": { "list": {
                            "type": { "list": { "type": "int128", "length": 1 } },
                            "length": 1 }
                              },
                      "length": 2 }
                          }
                }
            },
            { "name": "pub-f01",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "none" } } }
            },
            { "name": "pub-f02",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "bool", "error": "none" } } }
            },
            { "name": "pub-f03",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "none", "error": "bool" } } }
            },
            { "name": "pub-f04",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "int128" } } }
            },
            { "name": "pub-f05",
                "access": "public",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": { "response": { "ok": "bool", "error": "none" } } }
            },
            { "name": "ro-f01",
                "access": "read_only",
                "args": [],
                "outputs": { "type": "int128" }
            },
            { "name": "ro-f02",
                "access": "read_only",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": "int128" }
            }
        ],
        "maps": [
            {
                "name": "map1",
                "key": {
                    "tuple": [{
                        "name": "name",
                        "type": "int128"
                    }]
                },
                "value": {
                    "tuple": [{
                        "name": "owner",
                        "type": "principal"
                    }]
                }
            },
            {
                "name": "map2",
                "key": {
                    "tuple": [{
                        "name": "k-name-1",
                        "type": "bool"
                    }]
                },
                "value": {
                    "tuple": [{
                        "name": "v-name-1",
                        "type": {
                            "buffer": { "length": 33 }
                        }
                    }]
                }
            },
            {
                "name": "map3",
                "key": {
                    "tuple": [{
                        "name": "k-name-2",
                        "type": "bool"
                    }]
                },
                "value": {
                    "tuple": [{
                        "name": "v-name-2",
                        "type": {
                            "tuple": [
                                {
                                    "name": "n1",
                                    "type": "int128"
                                },
                                {
                                    "name": "n2",
                                    "type": "bool"
                                }
                            ] 
                        }
                    }]
                }
            }
        ],
        "variables": [
            { "name": "var1", "access": "constant", "type": "principal" },
            { "name": "var2", "access": "constant", "type": "bool" },
            { "name": "var3", "access": "constant", "type": "int128" },
            { "name": "d-var1", "access": "variable", "type": "bool" },
            { "name": "d-var2", "access": "variable", "type": "int128" },
            { "name": "d-var3", "access": "variable", "type": { "buffer": { "length": 5 } } }
        ],
        "fungible_tokens": [],
        "non_fungible_tokens": [],
        "clarity_version": "Clarity2"
    }"#).unwrap();

    eprintln!("{}", test_contract_json_str);

    assert_json_eq!(test_contract_json, test_contract_json_expected);
}

#[apply(test_clarity_versions_contracts)]
fn test_names_tokens_contracts(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let tokens_contract_id = QualifiedContractIdentifier::local("tokens").unwrap();
    let names_contract_id = QualifiedContractIdentifier::local("names").unwrap();

    let mut tokens_contract = parse(&tokens_contract_id, SIMPLE_TOKENS, version, epoch).unwrap();
    let mut names_contract = parse(&names_contract_id, SIMPLE_NAMES, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(&tokens_contract_id, &mut tokens_contract, db, true)?;
        type_check(&names_contract_id, &mut names_contract, db, true)
    })
    .unwrap();
}

#[apply(test_clarity_versions_contracts)]
fn test_names_tokens_contracts_bad(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let broken_public = "
         (define-public (broken-cross-contract (name-hash (buff 20)) (name-price uint))
           (if (is-ok (contract-call? .tokens token-transfer
                 burn-address true))
               (begin (map-insert preorder-map
                 (tuple (name-hash name-hash))
                 (tuple (paid name-price)
                        (buyer tx-sender))) (ok u1))
               (err 1)))";

    let names_contract = format!(
        "{}
                 {}",
        SIMPLE_NAMES, broken_public
    );

    let tokens_contract_id = QualifiedContractIdentifier::local("tokens").unwrap();
    let names_contract_id = QualifiedContractIdentifier::local("names").unwrap();

    let mut tokens_contract = parse(&tokens_contract_id, SIMPLE_TOKENS, version, epoch).unwrap();
    let mut names_contract = parse(&names_contract_id, &names_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        db.test_insert_contract_hash(&tokens_contract_id);
        type_check(&tokens_contract_id, &mut tokens_contract, db, true)
    })
    .unwrap();

    let err = db
        .execute(|db| type_check(&names_contract_id, &mut names_contract, db, true))
        .unwrap_err();
    assert!(match &err.err {
        &CheckErrors::TypeError(ref expected_type, ref actual_type) => {
            eprintln!("Received TypeError on: {} {}", expected_type, actual_type);
            format!("{} {}", expected_type, actual_type) == "uint bool"
        }
        _ => false,
    });
}

#[test]
fn test_bad_map_usage() {
    let bad_fetch = "(define-map tokens { account: principal } { balance: int })
         (define-private (my-get-token-balance (account int))
            (let ((balance
                  (get balance (map-get? tokens (tuple (account account))))))
              balance))";
    let bad_delete = "(define-map tokens { account: principal } { balance: int })
         (define-private (del-balance (account principal))
            (map-delete tokens (tuple (balance account))))";
    let bad_set_1 = "(define-map tokens { account: principal } { balance: int })
         (define-private (set-balance (account principal))
            (map-set tokens (tuple (account account)) (tuple (balance \"foo\"))))";
    let bad_set_2 = "(define-map tokens { account: principal } { balance: int })
         (define-private (set-balance (account principal))
            (map-set tokens (tuple (account \"abc\")) (tuple (balance 0))))";
    let bad_insert_1 = "(define-map tokens { account: principal } { balance: int })
         (define-private (set-balance (account principal))
            (map-insert tokens (tuple (account account)) (tuple (balance \"foo\"))))";
    let bad_insert_2 = "(define-map tokens { account: principal } { balance: int })
         (define-private (set-balance (account principal))
            (map-insert tokens (tuple (account \"abc\")) (tuple (balance 0))))";

    let unhandled_option = "(define-map tokens { account: principal } { balance: int })
         (define-private (plus-balance (account principal))
           (+ (get balance (map-get? tokens (tuple (account account)))) 1))";

    let tests = [
        bad_fetch,
        bad_delete,
        bad_set_1,
        bad_set_2,
        bad_insert_1,
        bad_insert_2,
    ];

    for contract in tests.iter() {
        let err = mem_type_check(contract).unwrap_err();
        assert!(match err.err {
            CheckErrors::TypeError(_, _) => true,
            _ => false,
        });
    }

    assert!(match mem_type_check(unhandled_option).unwrap_err().err {
        // Bad arg to `+` causes a uniontype error
        CheckErrors::UnionTypeError(_, _) => true,
        _ => false,
    });
}

#[apply(test_clarity_versions_contracts)]
fn test_same_function_name(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let ca_id = QualifiedContractIdentifier::local("contract-a").unwrap();
    let cb_id = QualifiedContractIdentifier::local("contract-b").unwrap();

    let contract_b = "(define-read-only (foo-function (a int)) (+ a 1))";

    let contract_a = "(define-read-only (foo-function (a int))
           (contract-call? .contract-b foo-function a))";

    let mut ca = parse(&ca_id, contract_a, version, epoch).unwrap();
    let mut cb = parse(&cb_id, contract_b, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(&cb_id, &mut cb, db, true)?;
        type_check(&ca_id, &mut ca, db, true)
    })
    .unwrap();
}

#[test]
fn test_expects() {
    use crate::vm::analysis::type_check;
    let okay = "(define-map tokens { id: int } { balance: int })
         (define-private (my-get-token-balance)
            (let ((balance (unwrap!
                              (get balance (map-get? tokens (tuple (id 0))))
                              0)))
              (+ 0 balance)))
         (define-private (my-get-token-balance-2)
            (let ((balance
                    (get balance (unwrap! (map-get? tokens (tuple (id 0))) 0))
                              ))
              (+ 0 balance)))
          (define-private (my-get-token-balance-3)
             (let ((balance
                     (unwrap! (get balance (map-get? tokens (tuple (id 0))))
                              (err false))))
               (ok balance)))
          (define-private (my-get-token-balance-4)
             (unwrap! (my-get-token-balance-3) 0))

          (define-private (t-1)
             (err 3))
          (define-private (my-get-token-balance-5)
             (unwrap-err! (t-1) 0))

          (+ (my-get-token-balance) (my-get-token-balance-2) (my-get-token-balance-5))";

    let bad_return_types_tests = [
        "(define-map tokens { id: int } { balance: int })
         (define-private (my-get-token-balance)
            (let ((balance (unwrap!
                              (get balance (map-get? tokens (tuple (id 0))))
                              false)))
              (+ 0 balance)))",
        "(define-map tokens { id: int } { balance: int })
         (define-private (my-get-token-balance)
            (let ((balance (unwrap!
                              (get balance (map-get? tokens (tuple (id 0))))
                              (err 1))))
              (err false)))",
    ];

    let bad_default_type = "(define-map tokens { id: int } { balance: int })
         (default-to false (get balance (map-get? tokens (tuple (id 0)))))";

    let notype_response_type = "
         (define-private (t1) (ok 3))
         (define-private (t2) (unwrap-err! (t1) 0))
    ";

    let notype_response_type_2 = "
         (define-private (t1) (err 3))
         (define-private (t2) (unwrap! (t1) 0))
    ";

    mem_type_check(okay).unwrap();

    for unmatched_return_types in bad_return_types_tests.iter() {
        let err = mem_type_check(unmatched_return_types).unwrap_err();
        eprintln!("unmatched_return_types returned check error: {}", err);
        assert!(match &err.err {
            &CheckErrors::ReturnTypesMustMatch(_, _) => true,
            _ => false,
        })
    }

    let err = mem_type_check(bad_default_type).unwrap_err();
    eprintln!("bad_default_types returned check error: {}", err);
    assert!(match &err.err {
        &CheckErrors::DefaultTypesMustMatch(_, _) => true,
        _ => false,
    });

    let err = mem_type_check(notype_response_type).unwrap_err();
    eprintln!("notype_response_type returned check error: {}", err);
    assert!(match &err.err {
        &CheckErrors::CouldNotDetermineResponseErrType => true,
        _ => false,
    });

    let err = mem_type_check(notype_response_type_2).unwrap_err();
    eprintln!("notype_response_type_2 returned check error: {}", err);
    assert!(match &err.err {
        &CheckErrors::CouldNotDetermineResponseOkType => true,
        _ => false,
    });
}

#[test]
fn test_traits() {
    {
        let trait_to_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (internal-get-1 contract))
        (define-public (internal-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u1))";

        let trait_to_compatible_trait = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-trait trait-2 (
            (echo (uint) (response uint uint))
        ))
        (define-public (wrapped-echo (contract <trait-1>))
            (internal-echo contract))
        (define-public (internal-echo (contract <trait-2>))
            (ok true))";

        let bad_principal_to_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-public (wrapped-get-1 (contract principal))
            (internal-get-1 contract))
        (define-public (internal-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u1))";

        let bad_other_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-2 (
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-get-2 (contract <trait-1>))
            (internal-get-2 contract))
        (define-public (internal-get-2 (contract <trait-2>))
            (contract-call? contract get-2 u1))";

        let embedded_trait = "(define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-opt-get-1 (contract <trait-12>))
            (internal-get-1 (some contract)))
        (define-public (internal-get-1 (opt-contract (optional <trait-12>)))
            (match opt-contract
                contract (contract-call? contract get-1 u1)
                (err u1)
            )
        )";

        let embedded_trait_compatible = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-opt-get-1 (contract <trait-12>))
            (internal-get-1 (some contract)))
        (define-public (internal-get-1 (opt-contract (optional <trait-1>)))
            (match opt-contract
                contract (contract-call? contract get-1 u1)
                (err u1)
            )
        )";

        let bad_embedded_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-opt-get-1 (contract <trait-1>))
            ;; Passing (optional <trait-1>) as an (optional <trait-12>) should be an error
            (wrapped-get-1 (some contract)))
        (define-public (wrapped-get-1 (opt-contract (optional <trait-12>)))
            (internal-get-1 opt-contract)
        )
        (define-public (internal-get-1 (opt-contract (optional <trait-12>)))
            (match opt-contract
                contract (contract-call? contract get-1 u1)
                (err u1)
            )
        )";

        let let_trait = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-public (let-echo (t <trait-1>))
            (let ((t1 t))
                (contract-call? t1 echo u42)
            )
        )";

        let let3_trait = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-public (let-echo (t <trait-1>))
            (let ((t1 t))
                (let ((t2 t1))
                    (let ((t3 t2))
                        (contract-call? t3 echo u42)
                    )
                )
            )
        )";

        let trait_args_differ = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-trait trait-2 (
            (echo (int) (response uint uint))
        ))
        (define-public (wrapped-echo (contract <trait-1>))
            (internal-echo contract))
        (define-public (internal-echo (contract <trait-2>))
            (ok true))";

        let trait_ret_ty_differ = "(define-trait trait-1 (
            (echo (uint) (response int uint))
        ))
        (define-trait trait-2 (
            (echo (uint) (response uint uint))
        ))
        (define-public (wrapped-echo (contract <trait-1>))
            (internal-echo contract))
        (define-public (internal-echo (contract <trait-2>))
            (contract-call? contract echo u1))";

        let trait_with_compatible_trait_arg = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-trait trait-2 (
            (echo (uint) (response uint uint))
        ))
        (define-trait trait-a (
            (echo (<trait-1>) (response uint uint))
        ))
        (define-trait trait-b (
            (echo (<trait-2>) (response uint uint))
        ))
        (define-public (wrapped-echo (contract <trait-a>))
            (internal-echo contract))
        (define-public (internal-echo (contract <trait-b>) (callee <trait-2>))
            (contract-call? contract echo callee))";

        let trait_with_bad_trait_arg = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-trait trait-2 (
            (echo (uint) (response int uint))
        ))
        (define-trait trait-a (
            (echo (<trait-1>) (response uint uint))
        ))
        (define-trait trait-b (
            (echo (<trait-2>) (response uint uint))
        ))
        (define-public (wrapped-echo (contract <trait-a>))
            (internal-echo contract))
        (define-public (internal-echo (contract <trait-b>) (callee <trait-2>))
            (contract-call? contract echo callee))";

        let trait_with_superset_trait_arg = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-trait trait-2 (
            (echo (uint) (response uint uint))
            (foo (uint) (response uint uint))
        ))
        (define-trait trait-a (
            (echo (<trait-1>) (response uint uint))
        ))
        (define-trait trait-b (
            (echo (<trait-2>) (response uint uint))
        ))
        (define-public (wrapped-echo (contract <trait-a>))
            (internal-echo contract))
        (define-public (internal-echo (contract <trait-b>) (callee <trait-2>))
            (contract-call? contract echo callee))";

        let trait_with_subset_trait_arg = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-trait trait-2 (
            (echo (uint) (response uint uint))
            (foo (uint) (response uint uint))
        ))
        (define-trait trait-a (
            (echo (<trait-1>) (response uint uint))
        ))
        (define-trait trait-b (
            (echo (<trait-2>) (response uint uint))
        ))
        (define-public (wrapped-echo (contract <trait-b>))
            (internal-echo contract))
        (define-public (internal-echo (contract <trait-a>) (callee <trait-1>))
            (contract-call? contract echo callee))";

        mem_type_check(trait_to_trait).unwrap();
        mem_type_check(trait_to_compatible_trait).unwrap();

        let err = mem_type_check(bad_principal_to_trait).unwrap_err();
        eprintln!("pass principal value to trait param: {}", err);
        assert!(match err {
            CheckError {
                err: CheckErrors::TypeError(expected, found),
                expressions: _,
                diagnostic: _,
            } => {
                match (expected, found) {
                    (
                        TypeSignature::TraitReferenceType(expected_trait),
                        TypeSignature::PrincipalType,
                    ) => {
                        assert_eq!(expected_trait.name.as_str(), "trait-1");
                        true
                    }
                    _ => false,
                }
            }
            _ => false,
        });

        let err = mem_type_check(bad_other_trait).unwrap_err();
        eprintln!("pass invalid embedded trait to trait param: {}", err);
        assert!(match err {
            CheckError {
                err: CheckErrors::IncompatibleTrait(expected, actual),
                expressions: _,
                diagnostic: _,
            } => {
                assert_eq!(expected.name.as_str(), "trait-2");
                assert_eq!(actual.name.as_str(), "trait-1");
                true
            }
            _ => false,
        });

        mem_type_check(embedded_trait).unwrap();
        mem_type_check(embedded_trait_compatible).unwrap();

        let err = mem_type_check(bad_embedded_trait).unwrap_err();
        eprintln!("pass invalid embedded trait to trait param: {}", err);
        assert!(match err {
            CheckError {
                err: CheckErrors::IncompatibleTrait(expected, actual),
                expressions: _,
                diagnostic: _,
            } => {
                assert_eq!(expected.name.as_str(), "trait-12");
                assert_eq!(actual.name.as_str(), "trait-1");
                true
            }
            _ => false,
        });

        mem_type_check(let_trait).unwrap();
        mem_type_check(let3_trait).unwrap();

        let err = mem_type_check(trait_args_differ).unwrap_err();
        eprintln!("pass trait with different arg type to trait param: {}", err);
        assert!(match err {
            CheckError {
                err: CheckErrors::IncompatibleTrait(expected, actual),
                expressions: _,
                diagnostic: _,
            } => {
                assert_eq!(expected.name.as_str(), "trait-2");
                assert_eq!(actual.name.as_str(), "trait-1");
                true
            }
            _ => false,
        });

        let err = mem_type_check(trait_ret_ty_differ).unwrap_err();
        eprintln!(
            "pass trait with different return type to trait param: {}",
            err
        );
        assert!(match err {
            CheckError {
                err: CheckErrors::IncompatibleTrait(expected, actual),
                expressions: _,
                diagnostic: _,
            } => {
                assert_eq!(expected.name.as_str(), "trait-2");
                assert_eq!(actual.name.as_str(), "trait-1");
                true
            }
            _ => false,
        });

        mem_type_check(trait_with_compatible_trait_arg).unwrap();

        let err = mem_type_check(trait_with_bad_trait_arg).unwrap_err();
        eprintln!(
            "trait with trait argument, pass incompatible trait: {}",
            err
        );
        assert!(match err {
            CheckError {
                err: CheckErrors::IncompatibleTrait(expected, actual),
                expressions: _,
                diagnostic: _,
            } => {
                assert_eq!(expected.name.as_str(), "trait-b");
                assert_eq!(actual.name.as_str(), "trait-a");
                true
            }
            _ => false,
        });
    }
}
