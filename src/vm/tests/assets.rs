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

const ASSET_NAMES: &str =
        "(define burn-address 'SP000000000000000000002Q6VF78)
         (define (price-function (name int))
           (if (< name 100000) 1000 100))
         
         (define-asset names int)
         (define-map preorder-map
           ((name-hash (buff 20)))
           ((buyer principal) (paid int)))
         
         (define-public (preorder 
                        (name-hash (buff 20))
                        (name-price int))
           (let ((xfer-result (contract-call! tokens my-token-transfer
                                burn-address name-price)))
            (if (is-ok? xfer-result)
               (if
                 (insert-entry! preorder-map
                   (tuple (name-hash name-hash))
                   (tuple (paid name-price)
                          (buyer tx-sender)))
                 (ok 0) (err 2))
               (if (eq? xfer-result (err 1)) ;; not enough balance
                   (err 1) (err 3)))))

         (define-public (register 
                        (recipient-principal principal)
                        (name int)
                        (salt int))
           (let ((preorder-entry
                   ;; preorder entry must exist!
                   (expects! (fetch-entry preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 5)))
                 (name-entry 
                   (get-owner names name)))
             (if (and
                  (is-none? name-entry)
                  ;; preorder must have paid enough
                  (<= (price-function name) 
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (eq? tx-sender
                       (get buyer preorder-entry)))
                  (if (and
                    (is-ok? (mint-asset! names name recipient-principal))
                    (delete-entry! preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                    (ok 0)
                    (err 3))
                  (err 4))))";

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

#[test]
fn test_simple_naming_system() {
    let tokens_contract = FIRST_CLASS_TOKENS;

    let names_contract = ASSET_NAMES;

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let name_hash_expensive_0 = execute("(hash160 1)");
    let name_hash_expensive_1 = execute("(hash160 2)");
    let name_hash_cheap_0 = execute("(hash160 100001)");

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    {
        let mut env = owned_env.get_exec_environment(None);

        env.initialize_contract("tokens", tokens_contract).unwrap();
        env.initialize_contract("names", names_contract).unwrap();
    }

    {
        let mut env = owned_env.get_exec_environment(Some(p2.clone()));

        assert!(is_err_code(&
                            env.execute_contract("names", "preorder",
                                                 &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(), 1));
    }

    {
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert!(is_committed(&
                             env.execute_contract("names", "preorder",
                                                  &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap()));
        assert!(is_err_code(&
                            env.execute_contract("names", "preorder",
                                                 &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(), 2));
    }

    {
        // shouldn't be able to register a name you didn't preorder!
        let mut env = owned_env.get_exec_environment(Some(p2.clone()));
        assert!(is_err_code(&
                            env.execute_contract("names", "register",
                                                 &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap(), 4));
    }

    {
        // should work!
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert!(is_committed(&
                             env.execute_contract("names", "register",
                                                  &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap()));

        assert_eq!(
            env.eval_read_only("names",
                               "(get-owner names 1)").unwrap(),
            Value::some(p2.clone()));
        
    }

    {
        // try to underpay!
        let mut env = owned_env.get_exec_environment(Some(p2.clone()));
        assert!(is_committed(&
                             env.execute_contract("names", "preorder",
                                                  &symbols_from_values(vec![name_hash_expensive_1.clone(), Value::Int(100)])).unwrap()));
        assert!(is_err_code(&
                            env.execute_contract("names", "register",
                                                 &symbols_from_values(vec![p2.clone(), Value::Int(2) , Value::Int(0)])).unwrap(), 4));
        
        // register a cheap name!
        assert!(is_committed(&
                             env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_cheap_0.clone(), Value::Int(100)])).unwrap()));
        assert!(is_committed(&
                             env.execute_contract("names", "register",
                             &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap()));
        
        // preorder must exist!
        assert!(is_err_code(&
                            env.execute_contract("names", "register",
                                                 &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap(), 5));
    }
}
