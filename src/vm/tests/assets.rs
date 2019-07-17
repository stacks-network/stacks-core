use vm::execute as vm_execute;
use vm::errors::{Error, UncheckedError};
use vm::types::{Value, PrincipalData, ResponseData};
use vm::contexts::{OwnedEnvironment,GlobalContext};
use vm::database::{ContractDatabaseConnection};
use vm::representations::SymbolicExpression;
use vm::contracts::Contract;
use util::hash::hex_bytes;

fn execute(s: &str) -> Value {
    vm_execute(s).unwrap().unwrap()
}

fn symbols_from_values(mut vec: Vec<Value>) -> Vec<SymbolicExpression> {
    vec.drain(..).map(|value| SymbolicExpression::atom_value(value)).collect()
}

const FIRST_CLASS_TOKENS: &str = "(define-token stackaroos)
         (define-read-only (get-balance (account principal))
            (get-token-balance stackaroos account))
         (define-public (my-token-transfer (to principal) (amount int))
            (transfer-token! stackaroos amount tx-sender to))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (transfer-token! stackaroos 1 tx-sender original-sender))))
         (define-public (mint-after (block-to-release int))
           (if (>= block-height block-to-release)
               (faucet)
               (err \"must be in the future\")))
         (begin (mint-token! stackaroos 10000 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
                (mint-token! stackaroos 200 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
                (mint-token! stackaroos 4   'CTtokens))";

fn is_committed(v: &Value) -> bool {
    match v {
        Value::Response(ref data) => data.committed,
        _ => false
    }
}

fn is_err_code(v: &Value, e: i128) -> bool {
    match v {
        Value::Response(ref data) => {
            !data.committed &&
                *data.data == Value::Int(e)
        },
        _ => false
    }
}

#[test]
fn test_simple_token_system() {
    let tokens_contract = FIRST_CLASS_TOKENS;

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    {
        let mut env = owned_env.get_exec_environment(None);

        env.initialize_contract("tokens", tokens_contract).unwrap();
    }

    {
        let mut env = owned_env.get_exec_environment(Some(p2.clone()));
        assert!(!is_committed(&env.execute_contract("tokens", "my-token-transfer",
                                                    &symbols_from_values(vec![p1.clone(), Value::Int(210)])).unwrap()));
    }

    {
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert!(is_committed(&
                             env.execute_contract("tokens", "my-token-transfer",
                                                  &symbols_from_values(vec![p2.clone(), Value::Int(9000)])).unwrap()));

        assert!(!is_committed(&
                              env.execute_contract("tokens", "my-token-transfer",
                                                   &symbols_from_values(vec![p2.clone(), Value::Int(1001)])).unwrap()));
        assert!(!is_committed(& // send to self!
                             env.execute_contract("tokens", "my-token-transfer",
                                                  &symbols_from_values(vec![p1.clone(), Value::Int(1000)])).unwrap()));
        
        assert_eq!(
            env.eval_read_only("tokens",
                               "(get-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)").unwrap(),
            Value::Int(1000));
        assert_eq!(
            env.eval_read_only("tokens",
                               "(get-balance 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)").unwrap(),
            Value::Int(9200));
        assert!(is_committed(&
                             env.execute_contract("tokens", "faucet", &vec![]).unwrap()));
        
        assert!(is_committed(&
                             env.execute_contract("tokens", "faucet", &vec![]).unwrap()));
        
        assert!(is_committed(&
                             env.execute_contract("tokens", "faucet", &vec![]).unwrap()));
        
        assert_eq!(
            env.eval_read_only("tokens",
                               "(get-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)").unwrap(),
            Value::Int(1003));
        assert!(!is_committed(&
                              env.execute_contract("tokens", "mint-after", &symbols_from_values(vec![Value::Int(25)])).unwrap()));
        
        env.global_context.database.sim_mine_blocks(10);
        assert!(is_committed(&
                             env.execute_contract("tokens", "mint-after", &symbols_from_values(vec![Value::Int(25)])).unwrap()));
        
        assert!(!is_committed(&
                              env.execute_contract("tokens", "faucet", &vec![]).unwrap()));
        
        assert_eq!(
            env.eval_read_only("tokens",
                               "(get-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)").unwrap(),
            Value::Int(1004));
        assert_eq!(
            env.execute_contract("tokens", "get-balance", &symbols_from_values(vec![p1.clone()])).unwrap(),
            Value::Int(1004));
    }
}
