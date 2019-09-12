use vm::errors::{Error, InterpreterResult as Result, RuntimeErrorType};
use vm::types::{Value};
use vm::contexts::{OwnedEnvironment};
use vm::representations::SymbolicExpression;
use vm::database::marf::temporary_marf;
use vm::database::ClarityDatabase;

use vm::tests::{symbols_from_values, execute, is_err_code, is_committed};

use chainstate::stacks::index::storage::{TrieFileStorage};
use chainstate::burn::BlockHeaderHash;

const p1_str: &str = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR";

#[test]
fn test_forking_simple() {
    with_separate_forks_environment(
        initialize_contract,
        |x| { branched_execution(x, true); },
        |x| { branched_execution(x, true); },
        |x| { branched_execution(x, false); });
}

#[test]
fn test_at_block_good() {
    fn initialize(owned_env: &mut OwnedEnvironment) {
        let contract =
            "(define-data-var datum int 1)
             (define-public (reset)
               (begin
                 (var-set! datum (+
                   (at-block 0x0202020202020202020202020202020202020202020202020202020202020202 (var-get datum))
                   (at-block 0x0101010101010101010101010101010101010101010101010101010101010101 (var-get datum))))
                 (ok (var-get datum))))
             (define-public (set-val)
               (begin
                 (var-set! datum 10)
                 (ok (var-get datum))))";

        eprintln!("Initializing contract...");
        owned_env.begin();
        owned_env.initialize_contract("contract", &contract).unwrap();
        owned_env.commit().unwrap();
    }


    fn branch(owned_env: &mut OwnedEnvironment, expected_value: i128, to_exec: &str) -> Result<Value> {
        let p1 = execute(p1_str);
        eprintln!("Branched execution...");

        {
            let mut env = owned_env.get_exec_environment(None);
            let command = format!("(var-get datum)");
            let value = env.eval_read_only("contract", &command).unwrap();
            assert_eq!(value, Value::Int(expected_value));
        }
        
        owned_env.execute_transaction(p1, "contract", to_exec, &vec![])
            .map(|(x, _)| x)
    }

    with_separate_forks_environment(
        initialize,
        |x| {
            assert_eq!(branch(x, 1, "set-val").unwrap(),
                       Value::okay(Value::Int(10)));
        },
        |x| {
            let resp = branch(x, 1, "reset").unwrap_err();
            eprintln!("{}", resp);
            match resp {
                Error::Runtime(x, _) =>
                    assert_eq!(x, RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash::from(vec![2 as u8; 32].as_slice()))),
                _ => panic!("Unexpected error")
            }
        },
        |x| {
            assert_eq!(branch(x, 10, "reset").unwrap(),
                       Value::okay(Value::Int(11)));
        });
}

// execute:
// f -> a -> z
//    \--> b
// with f @ block 1;32
// with a @ block 2;32
// with b @ block 3;32
// with z @ block 4;32

fn with_separate_forks_environment<F0, F1, F2, F3>(f: F0, a: F1, b: F2, z: F3)
where F0: FnOnce(&mut OwnedEnvironment),
      F1: FnOnce(&mut OwnedEnvironment),
      F2: FnOnce(&mut OwnedEnvironment),
      F3: FnOnce(&mut OwnedEnvironment)
{
    let mut marf_kv = temporary_marf();
    marf_kv.begin(&TrieFileStorage::block_sentinel(),
                  &BlockHeaderHash::from_bytes(&[0 as u8; 32]).unwrap());

    {
        let mut clarity_db = ClarityDatabase::new(Box::new(&mut marf_kv));
        clarity_db.initialize();
    }

    marf_kv.commit();
    marf_kv.begin(&BlockHeaderHash::from_bytes(&[0 as u8; 32]).unwrap(),
                  &BlockHeaderHash::from_bytes(&[1 as u8; 32]).unwrap());

    {
        let clarity_db = ClarityDatabase::new(Box::new(&mut marf_kv));
        let mut owned_env = OwnedEnvironment::new(clarity_db);
        f(&mut owned_env)
    }

    marf_kv.commit();

    // Now, we can do our forking.

    marf_kv.begin(&BlockHeaderHash::from_bytes(&[1 as u8; 32]).unwrap(),
                  &BlockHeaderHash::from_bytes(&[2 as u8; 32]).unwrap());

    {
        let clarity_db = ClarityDatabase::new(Box::new(&mut marf_kv));
        let mut owned_env = OwnedEnvironment::new(clarity_db);
        a(&mut owned_env)
    }

    marf_kv.commit();

    marf_kv.begin(&BlockHeaderHash::from_bytes(&[1 as u8; 32]).unwrap(),
                  &BlockHeaderHash::from_bytes(&[3 as u8; 32]).unwrap());

    {
        let clarity_db = ClarityDatabase::new(Box::new(&mut marf_kv));
        let mut owned_env = OwnedEnvironment::new(clarity_db);
        b(&mut owned_env)
    }

    marf_kv.commit();


    marf_kv.begin(&BlockHeaderHash::from_bytes(&[2 as u8; 32]).unwrap(),
                  &BlockHeaderHash::from_bytes(&[4 as u8; 32]).unwrap());

    {
        let clarity_db = ClarityDatabase::new(Box::new(&mut marf_kv));
        let mut owned_env = OwnedEnvironment::new(clarity_db);
        z(&mut owned_env)
    }

    marf_kv.commit();
    
}

fn initialize_contract(owned_env: &mut OwnedEnvironment) {
    let contract = format!(
        "(define-constant burn-address 'SP000000000000000000002Q6VF78)
         (define-fungible-token stackaroos)
         (define-read-only (get-balance (p principal))
           (ft-get-balance stackaroos p))
         (define-public (destroy (x int))
           (if (< (ft-get-balance stackaroos tx-sender) x)
               (err -1)
               (ft-transfer! stackaroos x tx-sender burn-address)))
         (ft-mint! stackaroos 10 {})", p1_str);

    eprintln!("Initializing contract...");
    owned_env.begin();
    owned_env.initialize_contract("tokens", &contract).unwrap();
    owned_env.commit().unwrap();
}

fn branched_execution(owned_env: &mut OwnedEnvironment, expect_success: bool) {
    let p1 = execute(p1_str);
    eprintln!("Branched execution...");

    {
        let mut env = owned_env.get_exec_environment(None);
        let command = format!("(get-balance {})", p1_str);
        let balance = env.eval_read_only("tokens", &command).unwrap();
        let expected = if expect_success {
            10
        } else {
            0
        };
        assert_eq!(balance, Value::Int(expected));
    }

    let (result, _) = owned_env.execute_transaction(p1, "tokens", "destroy",
                                                    &symbols_from_values(vec![Value::Int(10)])).unwrap();

    if expect_success {
        assert!(is_committed(&result))
    } else {
        assert!(is_err_code(&result, -1))
    }
}

