use vm::execute as vm_execute;
use vm::errors::{Error, CheckErrors, RuntimeErrorType};
use vm::types::{Value, PrincipalData, ResponseData, QualifiedContractIdentifier, AssetIdentifier};
use vm::contexts::{OwnedEnvironment, GlobalContext, AssetMap, AssetMapEntry};
use vm::functions::NativeFunctions;
use vm::representations::SymbolicExpression;
use vm::contracts::Contract;
use util::hash::hex_bytes;
use vm::tests::{with_memory_environment, with_marfed_environment, symbols_from_values,
                execute, is_err_code, is_committed};

use vm::contexts::{Environment};
use vm::costs::{ExecutionCost};
use vm::database::{ClarityDatabase, MarfedKV, MemoryBackingStore,
                   NULL_HEADER_DB};
use chainstate::stacks::events::StacksTransactionEvent;
use chainstate::stacks::index::storage::{TrieFileStorage};
use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::index::MarfTrieId;
use chainstate::stacks::StacksBlockId;

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
        Print => "(print 1)",
        ContractCall => "(contract-call? .contract-other foo-exec 1)",
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
        AtBlock => "(at-block 0x0000000000000000000000000000000000000000000000000000000000000000 1)",
        GetStxBalance => "(stx-get-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        StxTransfer => "(stx-transfer? u1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        StxBurn => "(stx-burn? u1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
    }
}

fn execute_transaction(env: &mut OwnedEnvironment, issuer: Value, contract_identifier: &QualifiedContractIdentifier,
                       tx: &str, args: &[SymbolicExpression]) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), Error> {
    env.execute_transaction(issuer, contract_identifier.clone(), tx, args)
}

fn test_tracked_costs(prog: &str) -> ExecutionCost {
    let contract_other = "(define-map map-foo ((a int)) ((b int)))
                          (define-public (foo-exec (a int)) (ok 1))";

    let contract_self = format!("(define-map map-foo ((a int)) ((b int)))
                         (define-non-fungible-token nft-foo int)
                         (define-fungible-token ft-foo)
                         (define-data-var var-foo int 0)
                         (define-constant tuple-foo (tuple (a 1)))
                         (define-constant list-foo (list true))
                         (define-constant list-bar (list 1))
                         (define-public (execute) (ok {}))", prog);

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let p1_principal = match p1 {
        Value::Principal(PrincipalData::Standard(ref data)) => data.clone(),
        _ => panic!()
    };

    let self_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "self".into());
    let other_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "contract-other".into());

    let mut marf_kv = MarfedKV::temporary();
    marf_kv.begin(&TrieFileStorage::block_sentinel(),
                  &StacksBlockId([0 as u8; 32]));

    {
        marf_kv.as_clarity_db(&NULL_HEADER_DB).initialize();
    }

    marf_kv.test_commit();
    marf_kv.begin(&StacksBlockId([0 as u8; 32]),
                  &StacksBlockId([1 as u8; 32]));


    let mut owned_env = OwnedEnvironment::new(marf_kv.as_clarity_db(&NULL_HEADER_DB));


    owned_env.initialize_contract(other_contract_id.clone(), contract_other).unwrap();
    owned_env.initialize_contract(self_contract_id.clone(), &contract_self).unwrap();

    eprintln!("{}", &contract_self);
    execute_transaction(&mut owned_env, p2, &self_contract_id, "execute", &[]).unwrap();

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
