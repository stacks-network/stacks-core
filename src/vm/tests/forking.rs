use vm::types::{Value};
use vm::contexts::{OwnedEnvironment};
use vm::representations::SymbolicExpression;
use vm::database::marf::temporary_marf;
use vm::database::ClarityDatabase;

use vm::tests::{symbols_from_values, execute, is_err_code, is_committed};

use chainstate::stacks::index::storage::{TrieFileStorage};
use chainstate::burn::BlockHeaderHash;

#[test]
fn test_forking_simple() {
    with_separate_forks_environment(
        initialize_contract,
        |x| { branched_execution(x, true); },
        |x| { branched_execution(x, true); },
        |x| { branched_execution(x, false); });
}

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
    // Basically, what we're doing is:
    //  initialize -> f -> a  -> z
    //                 \--> b

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

const p1_str: &str = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR";

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

    let contract_identifier = QualifiedContractIdentifier::local("tokens")?;
    owned_env.initialize_contract(contract_identifier, &contract).unwrap();
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

