use vm::execute;
use vm::errors::{Error, ErrType};
use vm::types::{Value, PrincipalData};
use vm::contexts::{OwnedEnvironment};
use vm::database::{ContractDatabaseConnection};
use vm::representations::SymbolicExpression;

fn symbols_from_values(mut vec: Vec<Value>) -> Vec<SymbolicExpression> {
    vec.drain(..).map(|value| SymbolicExpression::atom_value(value)).collect()
}

#[test]
fn test_simple_token_system() {
    let tokens_contract = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (get-balance (account principal))
            (let ((balance
                  (get balance (fetch-entry tokens (tuple (account account))))))
              (if (eq? balance 'null) 0 balance)))

         (define (token-credit! (account principal) (tokens int))
            (if (<= tokens 0)
                'false
                (let ((current-amount (get-balance account)))
                  (begin
                    (set-entry! tokens (tuple (account account))
                                       (tuple (balance (+ tokens current-amount))))
                    'true))))
         (define-public (token-transfer (to principal) (amount int))
          (let ((balance (get-balance tx-sender)))
             (if (or (> amount balance) (<= amount 0))
                 'false
                 (begin
                   (set-entry! tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (token-transfer original-sender 1))))                     
         (begin (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10000)
                (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 100)
                (token-credit! 'CTtokens 3)
                'null)";


    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR").unwrap();
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G").unwrap();

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);

    env.initialize_contract("tokens", tokens_contract).unwrap();

    env.sender = Some(p2.clone());
    assert_eq!(
        env.execute_contract("tokens", "token-transfer",
                             &symbols_from_values(vec![p1.clone(), Value::Int(110)])).unwrap(),
        Value::Bool(false));
    env.sender = Some(p1.clone());
    assert_eq!(
        env.execute_contract("tokens", "token-transfer",
                             &symbols_from_values(vec![p2.clone(), Value::Int(9000)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        env.execute_contract("tokens", "token-transfer",
                             &symbols_from_values(vec![p2.clone(), Value::Int(1001)])).unwrap(),
        Value::Bool(false));
    assert_eq!( // send to self!
        env.execute_contract("tokens", "token-transfer",
                             &symbols_from_values(vec![p1.clone(), Value::Int(1000)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        env.eval_read_only("tokens",
                           "(get-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)").unwrap(),
        Value::Int(1000));
    assert_eq!(
        env.eval_read_only("tokens",
                           "(get-balance 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)").unwrap(),
        Value::Int(9100));
    assert_eq!(
        env.execute_contract("tokens", "faucet", &vec![]).unwrap(),
        Value::Bool(true));
    assert_eq!(
        env.execute_contract("tokens", "faucet", &vec![]).unwrap(),
        Value::Bool(true));
    assert_eq!(
        env.execute_contract("tokens", "faucet", &vec![]).unwrap(),
        Value::Bool(true));
    assert_eq!(
        env.execute_contract("tokens", "faucet", &vec![]).unwrap(),
        Value::Bool(false));
    assert_eq!(
        env.eval_read_only("tokens",
                           "(get-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)").unwrap(),
        Value::Int(1003));

}

#[test]
fn test_simple_naming_system() {
    let tokens_contract = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (get-balance (account principal))
            (let ((balance
                  (get balance (fetch-entry tokens (tuple (account account))))))
              (if (eq? balance 'null) 0 balance)))

         (define (token-credit! (account principal) (tokens int))
            (if (<= tokens 0)
                'false
                (let ((current-amount (get-balance account)))
                  (begin
                    (set-entry! tokens (tuple (account account))
                                       (tuple (balance (+ tokens current-amount))))
                    'true))))
         (define-public (token-transfer (to principal) (amount int))
          (let ((balance (get-balance tx-sender)))
             (if (or (> amount balance) (<= amount 0))
                 'false
                 (begin
                   (set-entry! tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))                     
         (begin (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10000)
                (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 300)
                'null)";

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
           (if (contract-call! tokens token-transfer
                 burn-address name-price)
               (insert-entry! preorder-map
                 (tuple (name-hash name-hash))
                 (tuple (paid name-price)
                        (buyer tx-sender)))
               'false))

         (define-public (register 
                        (recipient-principal principal)
                        (name int)
                        (salt int))
           (let ((preorder-entry
                   (fetch-entry preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))))
                 (name-entry 
                   (fetch-entry name-map (tuple (name name)))))
             (if (and
                  ;; must be preordered
                  (not (eq? preorder-entry 'null))
                  ;; name shouldn't *already* exist
                  (eq? name-entry 'null)
                  ;; preorder must have paid enough
                  (<= (price-function name) 
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (eq? tx-sender
                       (get buyer preorder-entry)))
                  (and
                    (insert-entry! name-map
                      (tuple (name name))
                      (tuple (owner recipient-principal)))
                    (delete-entry! preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                  'false)))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR").unwrap();
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G").unwrap();

    let name_hash_expensive_0 = execute("(hash160 1)").unwrap();
    let name_hash_expensive_1 = execute("(hash160 2)").unwrap();
    let name_hash_cheap_0 = execute("(hash160 100001)").unwrap();

    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);

    env.initialize_contract("tokens", tokens_contract).unwrap();
    env.initialize_contract("names", names_contract).unwrap();

    env.sender = Some(p2.clone());

    assert_eq!(
        env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(),
        Value::Bool(false));

    env.sender = Some(p1.clone());
    assert_eq!(
        env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(),
        Value::Bool(false));

    // shouldn't be able to register a name you didn't preorder!
    env.sender = Some(p2.clone());
    assert_eq!(
        env.execute_contract("names", "register",
                             &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap(),
        Value::Bool(false));
    // should work!
    env.sender = Some(p1.clone());
    assert_eq!(
        env.execute_contract("names", "register",
                             &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap(),
        Value::Bool(true));


    // try to underpay!
    env.sender = Some(p2.clone());
    assert_eq!(
        env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_expensive_1.clone(), Value::Int(100)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        env.execute_contract("names", "register",
                             &symbols_from_values(vec![p2.clone(), Value::Int(2) , Value::Int(0)])).unwrap(),
        Value::Bool(false));

    // register a cheap name!
    assert_eq!(
        env.execute_contract("names", "preorder",
                             &symbols_from_values(vec![name_hash_cheap_0.clone(), Value::Int(100)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        env.execute_contract("names", "register",
                             &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap(),
        Value::Bool(true));
}


#[test]
fn test_simple_contract_call() {
    let contract_1 =
        "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial (id int) (factorial int))
           (insert-entry! factorials (tuple (id id)) (tuple (current 1) (index factorial))))
         (define-public (compute (id int))
           (let ((entry (fetch-entry factorials (tuple (id id)))))
                (if (eq? entry 'null)
                    'false
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             'true
                             (begin
                               (set-entry! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               'true))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5)
               'null)
        ";
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
                               "(get current (fetch-entry factorials (tuple (id 8008))))").unwrap(),
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
     (eq? id value)))


(define (get-data (id int))
  (get value (fetch-entry data (tuple (id id)))))
";

    let contract_2 ="
(define-public (fail-in-other)
  (begin
    (contract-call! contract-1 modify-data 100 101)
    'true))

(define-public (fail-in-self)
  (begin
    (contract-call! contract-1 modify-data 105 105)
    'false))
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
        Value::Bool(true));

    assert_eq!(
        env.execute_contract("contract-1", "modify-data",
                             &symbols_from_values(vec![Value::Int(20), Value::Int(10)])).unwrap(),
        Value::Bool(false));
    
    assert_eq!(
        env.eval_read_only("contract-1", "(get-data 20)").unwrap(),
        Value::Void);

    assert_eq!(
        env.eval_read_only("contract-1", "(get-data 10)").unwrap(),
        Value::Int(10));

    assert_eq!(
        env.execute_contract("contract-2", "fail-in-other",
                             &symbols_from_values(vec![])).unwrap(),
        Value::Bool(true));

    assert_eq!(
        env.execute_contract("contract-2", "fail-in-self",
                             &symbols_from_values(vec![])).unwrap(),
        Value::Bool(false));

    assert_eq!(
        env.eval_read_only("contract-1", "(get-data 105)").unwrap(),
        Value::Void);


    assert_eq!(
        env.eval_read_only("contract-1", "(get-data 100)").unwrap(),
        Value::Void);

    
}

#[test]
fn test_factorial_contract() {
    let contract_defn =
        "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial (id int) (factorial int))
           (insert-entry! factorials (tuple (id id)) (tuple (current 1) (index factorial))))
         (define-public (compute (id int))
           (let ((entry (fetch-entry factorials (tuple (id id)))))
                (if (eq? entry 'null)
                    'false
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             'true
                             (begin
                               (set-entry! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               'true))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5)
               'null)
        ";


    let mut conn = ContractDatabaseConnection::memory().unwrap();
    let mut owned_env = OwnedEnvironment::new(&mut conn);

    let mut env = owned_env.get_exec_environment(None);

    env.initialize_contract("factorial", contract_defn).unwrap();

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
                                      &format!("(get current (fetch-entry factorials (tuple (id {}))))", arguments[0]))
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
                                          &symbols_from_values(vec![Value::Void]));
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
