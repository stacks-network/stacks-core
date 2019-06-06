use vm::execute as vm_execute;
use vm::errors::{Error, ErrType};
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

const FACTORIAL_CONTRACT: &str = "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial (id int) (factorial int))
           (print (insert-entry! factorials (tuple (id id)) (tuple (current 1) (index factorial)))))
         (define-public (compute (id int))
           (let ((entry (expects! (fetch-entry factorials (tuple (id id)))
                                 (err 'false))))
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             (ok 'true)
                             (begin
                               (set-entry! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               (ok 'false))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5))";

const SIMPLE_TOKENS: &str = "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (get-balance (account principal))
            (default-to 0 (get balance (fetch-entry tokens (tuple (account account))))))
         (define-read-only (explode (account principal))
             (delete-entry! tokens (tuple (account account))))
         (define (token-credit! (account principal) (tokens int))
            (if (<= tokens 0)
                (err \"must be positive\")
                (let ((current-amount (get-balance account)))
                  (begin
                    (set-entry! tokens (tuple (account account))
                                       (tuple (balance (+ tokens current-amount))))
                    (ok 0)))))
         (define-public (token-transfer (to principal) (amount int))
          (let ((balance (get-balance tx-sender)))
             (if (or (> amount balance) (<= amount 0))
                 (err \"not enough balance\")
                 (begin
                   (set-entry! tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (token-transfer original-sender 1))))                     
         (define-public (mint-after (block-to-release int))
           (if (>= block-height block-to-release)
               (faucet)
               (err \"must be in the future\")))
         (begin (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10000)
                (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 200)
                (token-credit! 'CTtokens 4))";

#[test]
fn test_get_block_info_eval(){
    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);
    let env = owned_env.get_exec_environment(None);

    let contracts = [
        "(define (test-func) (get-block-info time 1))",
        "(define (test-func) (get-block-info time 100000))",
        "(define (test-func) (get-block-info time (- 1)))",
        "(define (test-func) (get-block-info time 'true))",
        "(define (test-func) (get-block-info header-hash 1))",
        "(define (test-func) (get-block-info burnchain-header-hash 1))",
        "(define (test-func) (get-block-info vrf-seed 1))",
    ];

    let expected = [
        Ok(Value::Int(env.global_context.get_block_time(1) as i128)),
        Err(true),
        Err(true),
        Err(true),
        Ok(Value::buff_from(hex_bytes("0200000000000000000000000000000000000000000000000000000000000001").unwrap()).unwrap()),
        Ok(Value::buff_from(hex_bytes("0300000000000000000000000000000000000000000000000000000000000001").unwrap()).unwrap()),
        Ok(Value::buff_from(hex_bytes("0100000000000000000000000000000000000000000000000000000000000001").unwrap()).unwrap()),
    ];

    for i in 0..contracts.len() {
        let mut nested_context = GlobalContext::begin_from(&mut env.global_context.database);
        let contract = Contract::initialize("test-contract", contracts[i],
                                            &mut nested_context).unwrap();
        {
            nested_context.database.insert_contract("test-contract", contract);
        }
        {
            let mut owned_env = OwnedEnvironment::new(&mut nested_context.database);
            let mut env = owned_env.get_exec_environment(None);
            let eval_result = env.eval_read_only("test-contract", "(test-func)");
            match &expected[i] {
                Ok(val) => assert_eq!(val, &eval_result.unwrap()),
                Err(_) => assert!(eval_result.is_err()),
            }
        }
        nested_context.database.roll_back();
    }
}

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
    let tokens_contract = SIMPLE_TOKENS;

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);

    env.initialize_contract("tokens", tokens_contract).unwrap();

    env.sender = Some(p2.clone());
    assert!(!is_committed(&env.execute_contract("tokens", "token-transfer",
                                               &symbols_from_values(vec![p1.clone(), Value::Int(210)])).unwrap()));

    env.sender = Some(p1.clone());
    assert!(is_committed(&
        env.execute_contract("tokens", "token-transfer",
                             &symbols_from_values(vec![p2.clone(), Value::Int(9000)])).unwrap()));

    assert!(!is_committed(&
        env.execute_contract("tokens", "token-transfer",
                             &symbols_from_values(vec![p2.clone(), Value::Int(1001)])).unwrap()));
    assert!(is_committed(& // send to self!
        env.execute_contract("tokens", "token-transfer",
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

#[test]
fn test_simple_naming_system() {
    let tokens_contract = SIMPLE_TOKENS;

    let names_contract =
        "(define burn-address 'SP000000000000000000002Q6VF78)
         (define (price-function (name int))
           (if (< name 100000) 1000 100))
         
         (define-map name-map 
           ((name int)) ((owner principal)))
         (define-map preorder-map
           ((name-hash (buff 20)))
           ((buyer principal) (paid int)))
         
         (define-public (preorder 
                        (name-hash (buff 20))
                        (name-price int))
           (let ((xfer-result (contract-call! tokens token-transfer
                                  burn-address name-price)))
            (if (is-ok? xfer-result)
               (if
                 (insert-entry! preorder-map
                   (tuple (name-hash name-hash))
                   (tuple (paid name-price)
                          (buyer tx-sender)))
                 (ok 0) (err 2))
               (if (eq? (expects-err! xfer-result (err (- 1)))
                        \"not enough balance\")
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
                   (fetch-entry name-map (tuple (name name)))))
             (if (and
                  (is-none? name-entry)
                  ;; preorder must have paid enough
                  (<= (price-function name) 
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (eq? tx-sender
                       (get buyer preorder-entry)))
                  (if (and
                    (insert-entry! name-map
                      (tuple (name name))
                      (tuple (owner recipient-principal)))
                    (delete-entry! preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                    (ok 0)
                    (err 3))
                  (err 4))))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let name_hash_expensive_0 = execute("(hash160 1)");
    let name_hash_expensive_1 = execute("(hash160 2)");
    let name_hash_cheap_0 = execute("(hash160 100001)");

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);

    env.initialize_contract("tokens", tokens_contract).unwrap();
    env.initialize_contract("names", names_contract).unwrap();

    env.sender = Some(p2.clone());

    assert!(is_err_code(&
        env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(), 1));

    env.sender = Some(p1.clone());
    assert!(is_committed(&
        env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap()));
    assert!(is_err_code(&
        env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(), 2));

    // shouldn't be able to register a name you didn't preorder!
    env.sender = Some(p2.clone());
    assert!(is_err_code(&
        env.execute_contract("names", "register",
                             &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap(), 4));

    // should work!
    env.sender = Some(p1.clone());
    assert!(is_committed(&
        env.execute_contract("names", "register",
                             &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap()));


    // try to underpay!
    env.sender = Some(p2.clone());
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


#[test]
fn test_simple_contract_call() {
    let contract_1 = FACTORIAL_CONTRACT;
    let contract_2 =
        "(define-public (proxy-compute)
            (contract-call! factorial-contract compute 8008))
        ";

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);

    env.initialize_contract("factorial-contract", contract_1).unwrap();
    env.initialize_contract("proxy-compute", contract_2).unwrap();

    let args = symbols_from_values(vec![]);
    env.sender = Some(Value::Principal(PrincipalData::StandardPrincipal
                                       (1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1])));

    let expected = [Value::Int(5),
                    Value::Int(20),
                    Value::Int(60),
                    Value::Int(120),
                    Value::Int(120),
                    Value::Int(120)];
    for expected_result in &expected {
        env.execute_contract("proxy-compute", "proxy-compute", &args).unwrap();
        assert_eq!(
            env.eval_read_only("factorial-contract",
                               "(get current (expects! (fetch-entry factorials (tuple (id 8008))) 'false))").unwrap(),
            *expected_result);
    }
}

#[test]
fn test_aborts() {
    let contract_1 ="
(define-map data ((id int)) ((value int)))

;; this will return false if id != value,
;;   which _aborts_ any data that is modified during
;;   the routine.
(define-public (modify-data
                 (id int)
                 (value int))
   (begin
     (set-entry! data (tuple (id id))
                      (tuple (value value)))
     (if (eq? id value)
         (ok 1)
         (err 1))))


(define (get-data (id int))
  (default-to 0
    (get value 
     (fetch-entry data (tuple (id id))))))
";

    let contract_2 ="
(define-public (fail-in-other)
  (begin
    (contract-call! contract-1 modify-data 100 101)
    (ok 1)))

(define-public (fail-in-self)
  (begin
    (contract-call! contract-1 modify-data 105 105)
    (err 1)))
";

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);

    env.initialize_contract("contract-1", contract_1).unwrap();
    env.initialize_contract("contract-2", contract_2).unwrap();

    env.sender = Some(Value::Principal(PrincipalData::StandardPrincipal
                                       (1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1])));

    assert_eq!(
        env.execute_contract("contract-1", "modify-data",
                             &symbols_from_values(vec![Value::Int(10), Value::Int(10)])).unwrap(),
        Value::Response(ResponseData{ committed: true, data: Box::new(Value::Int(1)) }));

    assert_eq!(
        env.execute_contract("contract-1", "modify-data",
                             &symbols_from_values(vec![Value::Int(20), Value::Int(10)])).unwrap(),
        Value::Response(ResponseData{ committed: false, data: Box::new(Value::Int(1)) }));
    
    assert_eq!(
        env.eval_read_only("contract-1", "(get-data 20)").unwrap(),
        Value::Int(0));

    assert_eq!(
        env.eval_read_only("contract-1", "(get-data 10)").unwrap(),
        Value::Int(10));

    assert_eq!(
        env.execute_contract("contract-2", "fail-in-other",
                             &symbols_from_values(vec![])).unwrap(),
        Value::Response(ResponseData{ committed: true, data: Box::new(Value::Int(1)) }));

    assert_eq!(
        env.execute_contract("contract-2", "fail-in-self",
                             &symbols_from_values(vec![])).unwrap(),
        Value::Response(ResponseData{ committed: false, data: Box::new(Value::Int(1)) }));

    assert_eq!(
        env.eval_read_only("contract-1", "(get-data 105)").unwrap(),
        Value::Int(0));


    assert_eq!(
        env.eval_read_only("contract-1", "(get-data 100)").unwrap(),
        Value::Int(0));

    
}

#[test]
fn test_factorial_contract() {
    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);

    env.initialize_contract("factorial", FACTORIAL_CONTRACT).unwrap();

    let tx_name = "compute";
    let arguments_to_test = [symbols_from_values(vec![Value::Int(1337)]),  
                             symbols_from_values(vec![Value::Int(1337)]),
                             symbols_from_values(vec![Value::Int(1337)]),
                             symbols_from_values(vec![Value::Int(1337)]),
                             symbols_from_values(vec![Value::Int(1337)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)]),
                             symbols_from_values(vec![Value::Int(8008)])];


    let expected = vec![
        Value::Int(3),
        Value::Int(6),
        Value::Int(6),
        Value::Int(6),
        Value::Int(6),
        Value::Int(5),
        Value::Int(20),
        Value::Int(60),
        Value::Int(120),
        Value::Int(120),
        Value::Int(120),
    ];
        
    env.sender = Some(Value::Principal(PrincipalData::StandardPrincipal
                                       (1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1])));

    for (arguments, expectation) in arguments_to_test.iter().zip(expected.iter()) {
        env.execute_contract("factorial", &tx_name, arguments).unwrap();

        assert_eq!(*expectation,
                   env.eval_read_only("factorial",
                                      &format!("(expects! (get current (fetch-entry factorials (tuple (id {})))) 'false)", arguments[0]))
                   .unwrap());
    }

    let err_result = env.execute_contract("factorial", "init-factorial",
                                          &symbols_from_values(vec![Value::Int(9000),
                                                                    Value::Int(15)]));
    match err_result {
        Err(Error{
            err_type: ErrType::NonPublicFunction(_),
            stack_trace: _ }) => {},
        _ => {
            println!("{:?}", err_result);
            panic!("Attempt to call init-factorial should fail!")
        }
    }

    let err_result = env.execute_contract("factorial", "compute",
                                          &symbols_from_values(vec![Value::Bool(true)]));
    match err_result {
        Err(Error{
            err_type: ErrType::TypeError(_, _),
            stack_trace: _ }) => {},
        _ => {
            println!("{:?}", err_result);
            assert!(false, "Attempt to call compute with void type should fail!")
        }
    }

}
