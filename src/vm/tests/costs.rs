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

use util::hash::hex_bytes;
use vm::contexts::{AssetMap, AssetMapEntry, GlobalContext, OwnedEnvironment};
use vm::contracts::Contract;
use vm::errors::{CheckErrors, Error, RuntimeErrorType};
use vm::execute as vm_execute;
use vm::functions::NativeFunctions;
use vm::representations::SymbolicExpression;
use vm::tests::{
    execute, is_committed, is_err_code, symbols_from_values, with_marfed_environment,
    with_memory_environment,
};
use vm::types::{AssetIdentifier, PrincipalData, QualifiedContractIdentifier, ResponseData, Value};

use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::events::StacksTransactionEvent;
use chainstate::stacks::index::storage::TrieFileStorage;
use chainstate::stacks::index::MarfTrieId;
use chainstate::stacks::StacksBlockId;
use vm::contexts::Environment;
use vm::costs::ExecutionCost;
use vm::database::{
    ClarityDatabase, MarfedKV, MemoryBackingStore, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};

use chainstate::stacks::StacksBlockHeader;
use core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use core::FIRST_STACKS_BLOCK_HASH;

pub fn get_simple_test(function: &NativeFunctions) -> &'static str {
    use vm::functions::NativeFunctions::*;
    match function {
        Add => "(+ 1 1)",
        ToUInt => "(to-uint 1)",
        ToInt => "(to-int u1)",
        Subtract => "(- 1 1)",
        Multiply => "(* 1 1)",
        Divide => "(/ 1 1)",
        CmpGeq => "(>= 2 1)",
        CmpLeq => "(<= 2 1)",
        CmpLess => "(< 2 1)",
        CmpGreater => "(> 2 1)",
        Modulo => "(mod 2 1)",
        Power => "(pow 2 3)",
        Sqrti => "(sqrti 81)",
        BitwiseXOR => "(xor 1 2)",
        And => "(and true false)",
        Or => "(or true false)",
        Not => "(not true)",
        Equals => "(is-eq 1 2)",
        If => "(if true (+ 1 2) 2)",
        Let => "(let ((x 1)) x)",
        FetchVar => "(var-get var-foo)",
        SetVar => "(var-set var-foo 1)",
        Map => "(map not list-foo)",
        Filter => "(filter not list-foo)",
        Fold => "(fold + list-bar 0)",
        Append => "(append list-bar 1)",
        Concat => "(concat list-bar list-bar)",
        AsMaxLen => "(as-max-len? list-bar u3)",
        Len => "(len list-bar)",
        ListCons => "(list 1 2 3 4)",
        FetchEntry => "(map-get? map-foo {a: 1})",
        SetEntry => "(map-set map-foo {a: 1} {b: 2})",
        InsertEntry => "(map-insert map-foo {a: 2} {b: 2})",
        DeleteEntry => "(map-delete map-foo {a: 1})",
        TupleCons => "(tuple (a 1))",
        TupleGet => "(get a tuple-foo)",
        Begin => "(begin 1)",
        Hash160 => "(hash160 1)",
        Sha256 => "(sha256 1)",
        Sha512 => "(sha512 1)",
        Sha512Trunc256 => "(sha512/256 1)",
        Keccak256 => "(keccak256 1)",
        Secp256k1Recover => "(secp256k1-recover? 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301)",
        Secp256k1Verify => "(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
        Print => "(print 1)",
        ContractCall => "(contract-call? .contract-other foo-exec 1)",
        ContractOf => "(contract-of contract)",
        PrincipalOf => "(principal-of? 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
        AsContract => "(as-contract 1)",
        GetBlockInfo => "(get-block-info? time u1)",
        ConsOkay => "(ok 1)",
        ConsError => "(err 1)",
        ConsSome => "(some 1)",
        DefaultTo => "(default-to 1 none)",
        Asserts => "(asserts! true (err 1))",
        UnwrapRet => "(unwrap! (ok 1) (err 1))",
        UnwrapErrRet => "(unwrap-err! (err 1) (ok 1))",
        Unwrap => "(unwrap-panic (ok 1))",
        UnwrapErr => "(unwrap-err-panic (err 1))",
        Match => "(match (some 1) x (+ x 1) 1)",
        TryRet => "(try! (if true (ok 1) (err 1)))",
        IsOkay => "(is-ok (ok 1))",
        IsNone => "(is-none none)",
        IsErr => "(is-err (err 1))",
        IsSome => "(is-some (some 1))",
        MintAsset => "(ft-mint? ft-foo u1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        MintToken => "(nft-mint? nft-foo 1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        GetTokenBalance => "(ft-get-balance ft-foo 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        GetAssetOwner => "(nft-get-owner? nft-foo 1)",
        TransferToken => "(ft-transfer? ft-foo u1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        TransferAsset => "(nft-transfer? nft-foo 1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        AtBlock => "(at-block 0x55c9861be5cff984a20ce6d99d4aa65941412889bdc665094136429b84f8c2ee 1)",   // first stacksblockid
        GetStxBalance => "(stx-get-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        StxTransfer => "(stx-transfer? u1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        StxBurn => "(stx-burn? u1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
    }
}

fn execute_transaction(
    env: &mut OwnedEnvironment,
    issuer: Value,
    contract_identifier: &QualifiedContractIdentifier,
    tx: &str,
    args: &[SymbolicExpression],
) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), Error> {
    env.execute_transaction(issuer, contract_identifier.clone(), tx, args)
}

fn test_tracked_costs(prog: &str) -> ExecutionCost {
    let contract_trait = "(define-trait trait-1 (
                            (foo-exec (int) (response int int))
                          ))";
    let contract_other = "(impl-trait .contract-trait.trait-1)
                          (define-map map-foo ((a int)) ((b int)))
                          (define-public (foo-exec (a int)) (ok 1))";

    let contract_self = format!(
        "(define-map map-foo ((a int)) ((b int)))
                         (define-non-fungible-token nft-foo int)
                         (define-fungible-token ft-foo)
                         (define-data-var var-foo int 0)
                         (define-constant tuple-foo (tuple (a 1)))
                         (define-constant list-foo (list true))
                         (define-constant list-bar (list 1))
                         (use-trait trait-1 .contract-trait.trait-1)
                         (define-public (execute (contract <trait-1>)) (ok {}))",
        prog
    );

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let p1_principal = match p1 {
        Value::Principal(PrincipalData::Standard(ref data)) => data.clone(),
        _ => panic!(),
    };

    let self_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "self".into());
    let other_contract_id =
        QualifiedContractIdentifier::new(p1_principal.clone(), "contract-other".into());
    let trait_contract_id =
        QualifiedContractIdentifier::new(p1_principal.clone(), "contract-trait".into());

    let mut marf_kv = MarfedKV::temporary();
    marf_kv.begin(
        &StacksBlockId::sentinel(),
        &StacksBlockHeader::make_index_block_hash(
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
        ),
    );

    {
        marf_kv
            .as_clarity_db(&NULL_HEADER_DB, &NULL_BURN_STATE_DB)
            .initialize();
    }

    marf_kv.test_commit();
    marf_kv.begin(
        &StacksBlockHeader::make_index_block_hash(
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
        ),
        &StacksBlockId([1 as u8; 32]),
    );

    let mut owned_env =
        OwnedEnvironment::new(marf_kv.as_clarity_db(&NULL_HEADER_DB, &NULL_BURN_STATE_DB));

    owned_env
        .initialize_contract(trait_contract_id.clone(), contract_trait)
        .unwrap();
    owned_env
        .initialize_contract(other_contract_id.clone(), contract_other)
        .unwrap();
    owned_env
        .initialize_contract(self_contract_id.clone(), &contract_self)
        .unwrap();

    let target_contract = Value::from(PrincipalData::Contract(other_contract_id));

    eprintln!("{}", &contract_self);
    execute_transaction(
        &mut owned_env,
        p2,
        &self_contract_id,
        "execute",
        &symbols_from_values(vec![target_contract]),
    )
    .unwrap();

    let (_db, tracker) = owned_env.destruct().unwrap();
    tracker.get_total()
}

#[test]
fn test_all() {
    let baseline = test_tracked_costs("1");

    for f in NativeFunctions::ALL.iter() {
        let test = get_simple_test(f);
        let cost = test_tracked_costs(test);
        assert!(cost.exceeds(&baseline));
    }
}
