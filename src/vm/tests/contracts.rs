use vm::execute as vm_execute;
use vm::errors::{Error, CheckErrors};
use vm::types::{Value, StandardPrincipalData, ResponseData, PrincipalData, QualifiedContractIdentifier};
use vm::contexts::{OwnedEnvironment,GlobalContext, Environment};
use vm::representations::SymbolicExpression;
use vm::contracts::Contract;
use util::hash::hex_bytes;
use vm::database::marf::temporary_marf;
use vm::database::ClarityDatabase;

use vm::tests::{with_memory_environment, with_marfed_environment, execute, symbols_from_values};

const FACTORIAL_CONTRACT: &str = "(define-map factorials ((id int)) ((current int) (index int)))
         (define-private (init-factorial (id int) (factorial int))
           (print (map-insert! factorials (tuple (id id)) (tuple (current 1) (index factorial)))))
         (define-public (compute (id int))
           (let ((entry (expects! (map-get factorials (tuple (id id)))
                                 (err 'false))))
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             (ok 'true)
                             (begin
                               (map-set! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               (ok 'false))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5))";

const SIMPLE_TOKENS: &str = "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (my-get-token-balance (account principal))
            (default-to 0 (get balance (map-get tokens (tuple (account account))))))
         (define-read-only (explode (account principal))
             (map-delete! tokens (tuple (account account))))
         (define-private (token-credit! (account principal) (amount int))
            (if (<= amount 0)
                (err \"must be positive\")
                (let ((current-amount (my-get-token-balance account)))
                  (begin
                    (map-set! tokens (tuple (account account))
                                       (tuple (balance (+ amount current-amount))))
                    (ok 0)))))
         (define-public (token-transfer (to principal) (amount int))
          (let ((balance (my-get-token-balance tx-sender)))
             (if (or (> amount balance) (<= amount 0))
                 (err \"not enough balance\")
                 (begin
                   (map-set! tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (print (token-transfer (print original-sender) 1)))))                     
         (define-public (mint-after (block-to-release int))
           (if (>= block-height block-to-release)
               (faucet)
               (err \"must be in the future\")))
         (begin (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10000)
                (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 200)
                (token-credit! .tokens 4))";


fn get_principal() -> Value {
    StandardPrincipalData::transient().into()
}

#[test]
fn test_get_block_info_eval(){

    let contracts = [
        "(define-private (test-func) (get-block-info time 1))",
        "(define-private (test-func) (get-block-info time 100000))",
        "(define-private (test-func) (get-block-info time (- 1)))",
        "(define-private (test-func) (get-block-info time 'true))",
        "(define-private (test-func) (get-block-info header-hash 1))",
        "(define-private (test-func) (get-block-info burnchain-header-hash 1))",
        "(define-private (test-func) (get-block-info vrf-seed 1))",
    ];

    let expected = [
        Ok(Value::Int(0)),
        Err(true),
        Err(true),
        Err(true),
        Ok(Value::buff_from(hex_bytes("0200000000000000000000000000000000000000000000000000000000000001").unwrap()).unwrap()),
        Ok(Value::buff_from(hex_bytes("0300000000000000000000000000000000000000000000000000000000000001").unwrap()).unwrap()),
        Ok(Value::buff_from(hex_bytes("0100000000000000000000000000000000000000000000000000000000000001").unwrap()).unwrap()),
    ];

    for i in 0..contracts.len() {
        let mut owned_env = OwnedEnvironment::memory();
        // start an initial transaction.
        owned_env.begin();
        let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();
        owned_env.initialize_contract(contract_identifier, contracts[i]).unwrap();

        let mut env = owned_env.get_exec_environment(None);

        let eval_result = env.eval_read_only(&QualifiedContractIdentifier::local("test-contract").unwrap(), 
                                             "(test-func)");
        match &expected[i] {
            Ok(val) => {
                match (val, &eval_result.unwrap()) {
                    (Value::Int(_), Value::Int(_)) => {},
                    (x, y) => assert_eq!(x, y)
                }
            },
            Err(_) => assert!(eval_result.is_err()),
        }
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

fn test_simple_token_system(owned_env: &mut OwnedEnvironment) {
    let tokens_contract = SIMPLE_TOKENS;

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    {
        let mut env = owned_env.get_exec_environment(None);

        let contract_identifier = QualifiedContractIdentifier::local("tokens").unwrap();
        env.initialize_contract(contract_identifier, tokens_contract).unwrap();
    }

    {
        let mut env = owned_env.get_exec_environment(Some(p2.clone()));
        assert!(!is_committed(&env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), 
                                                    "token-transfer",
                                                    &symbols_from_values(vec![p1.clone(), Value::Int(210)])).unwrap()));
    }

    {
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert!(is_committed(&
                             env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), 
                                                  "token-transfer",
                                                  &symbols_from_values(vec![p2.clone(), Value::Int(9000)])).unwrap()));

        assert!(!is_committed(&
                              env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), 
                                                   "token-transfer",
                                                   &symbols_from_values(vec![p2.clone(), Value::Int(1001)])).unwrap()));
        assert!(is_committed(& // send to self!
                             env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), "token-transfer",
                                                  &symbols_from_values(vec![p1.clone(), Value::Int(1000)])).unwrap()));
        
        assert_eq!(
            env.eval_read_only(&QualifiedContractIdentifier::local("tokens").unwrap(),
                               "(my-get-token-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)").unwrap(),
            Value::Int(1000));
        assert_eq!(
            env.eval_read_only(&QualifiedContractIdentifier::local("tokens").unwrap(),
                               "(my-get-token-balance 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)").unwrap(),
            Value::Int(9200));
        assert!(is_committed(&env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), 
                             "faucet", 
                             &vec![]).unwrap()));
        
        assert!(is_committed(&env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), 
                             "faucet", 
                             &vec![]).unwrap()));
        
        assert!(is_committed(&env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), 
                             "faucet", 
                             &vec![]).unwrap()));
        
        assert_eq!(
            env.eval_read_only(&QualifiedContractIdentifier::local("tokens").unwrap(),
                               "(my-get-token-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)").unwrap(),
                               Value::Int(1003));

        assert!(!is_committed(&env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), 
                              "mint-after", 
                              &symbols_from_values(vec![Value::Int(25)])).unwrap()));
        
        env.global_context.database.sim_mine_blocks(10);
        assert!(is_committed(&env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), 
                             "mint-after", 
                             &symbols_from_values(vec![Value::Int(25)])).unwrap()));
        
        assert!(!is_committed(&
                              env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), "faucet", &vec![]).unwrap()));
        
        assert_eq!(
            env.eval_read_only(&QualifiedContractIdentifier::local("tokens").unwrap(),
                               "(my-get-token-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)").unwrap(),
            Value::Int(1004));
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("tokens").unwrap(), "my-get-token-balance", &symbols_from_values(vec![p1.clone()])).unwrap(),
            Value::Int(1004));
    }
}

fn test_contract_caller(owned_env: &mut OwnedEnvironment) {
    let contract_a =
        "(define-read-only (get-caller)
           (list contract-caller tx-sender))";
    let contract_b =
        "(define-read-only (get-caller)
           (list contract-caller tx-sender))
         (define-read-only (as-contract-get-caller)
           (as-contract (get-caller)))
         (define-read-only (cc-get-caller)
           (contract-call! .contract-a get-caller))
         (define-read-only (as-contract-cc-get-caller)
           (as-contract (contract-call! .contract-a get-caller)))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("contract-a").unwrap(), contract_a).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("contract-b").unwrap(), contract_b).unwrap();
    }

    {
        let c_b = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("contract-b").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("contract-a").unwrap(), "get-caller", &vec![]).unwrap(),
            Value::list_from(vec![p1.clone(), p1.clone()]).unwrap());
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("contract-b").unwrap(), "as-contract-get-caller", &vec![]).unwrap(),
            Value::list_from(vec![c_b.clone(), c_b.clone()]).unwrap());
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("contract-b").unwrap(), "cc-get-caller", &vec![]).unwrap(),
            Value::list_from(vec![c_b.clone(), p1.clone()]).unwrap());
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("contract-b").unwrap(), "as-contract-cc-get-caller", &vec![]).unwrap(),
            Value::list_from(vec![c_b.clone(), c_b.clone()]).unwrap());
    }
}

fn test_fully_qualified_contract_call(owned_env: &mut OwnedEnvironment) {
    let contract_a =
        "(define-read-only (get-caller)
           (list contract-caller tx-sender))";
    let contract_b =
        "(define-read-only (get-caller)
           (list contract-caller tx-sender))
         (define-read-only (as-contract-get-caller)
           (as-contract (get-caller)))
         (define-read-only (cc-get-caller)
           (contract-call! 'S1G2081040G2081040G2081040G208105NK8PE5.contract-a get-caller))
         (define-read-only (as-contract-cc-get-caller)
           (as-contract (contract-call! .contract-a get-caller)))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None);
        env.initialize_contract(QualifiedContractIdentifier::local("contract-a").unwrap(), contract_a).unwrap();
        env.initialize_contract(QualifiedContractIdentifier::local("contract-b").unwrap(), contract_b).unwrap();
    }

    {
        let c_b = Value::from(PrincipalData::Contract(QualifiedContractIdentifier::local("contract-b").unwrap()));
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("contract-a").unwrap(), "get-caller", &vec![]).unwrap(),
            Value::list_from(vec![p1.clone(), p1.clone()]).unwrap());
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("contract-b").unwrap(), "as-contract-get-caller", &vec![]).unwrap(),
            Value::list_from(vec![c_b.clone(), c_b.clone()]).unwrap());
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("contract-b").unwrap(), "cc-get-caller", &vec![]).unwrap(),
            Value::list_from(vec![c_b.clone(), p1.clone()]).unwrap());
        assert_eq!(
            env.execute_contract(&QualifiedContractIdentifier::local("contract-b").unwrap(), "as-contract-cc-get-caller", &vec![]).unwrap(),
            Value::list_from(vec![c_b.clone(), c_b.clone()]).unwrap());
    }
}

fn test_simple_naming_system(owned_env: &mut OwnedEnvironment) {
    let tokens_contract = SIMPLE_TOKENS;

    let names_contract =
        "(define-constant burn-address 'SP000000000000000000002Q6VF78)
         (define-private (price-function (name int))
           (if (< name 100000) 1000 100))
         
         (define-map name-map 
           ((name int)) ((owner principal)))
         (define-map preorder-map
           ((name-hash (buff 20)))
           ((buyer principal) (paid int)))
         
         (define-public (preorder 
                        (name-hash (buff 20))
                        (name-price int))
           (let ((xfer-result (contract-call! .tokens token-transfer
                                  burn-address name-price)))
            (if (is-ok? xfer-result)
               (if
                 (map-insert! preorder-map
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
                   (expects! (map-get preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 5)))
                 (name-entry 
                   (map-get name-map (tuple (name name)))))
             (if (and
                  (is-none? name-entry)
                  ;; preorder must have paid enough
                  (<= (price-function name) 
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (eq? tx-sender
                       (get buyer preorder-entry)))
                  (if (and
                    (map-insert! name-map
                      (tuple (name name))
                      (tuple (owner recipient-principal)))
                    (map-delete! preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                    (ok 0)
                    (err 3))
                  (err 4))))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let name_hash_expensive_0 = execute("(hash160 1)");
    let name_hash_expensive_1 = execute("(hash160 2)");
    let name_hash_cheap_0 = execute("(hash160 100001)");

    {
        let mut env = owned_env.get_exec_environment(None);

        let contract_identifier = QualifiedContractIdentifier::local("tokens").unwrap();
        env.initialize_contract(contract_identifier, tokens_contract).unwrap();
        
        let contract_identifier = QualifiedContractIdentifier::local("names").unwrap();
        env.initialize_contract(contract_identifier, names_contract).unwrap();
    }

    {
        let mut env = owned_env.get_exec_environment(Some(p2.clone()));

        assert!(is_err_code(&
                            env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "preorder",
                                                 &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(), 1));
    }

    {
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert!(is_committed(&
                             env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "preorder",
                                                  &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap()));
        assert!(is_err_code(&
                            env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "preorder",
                                                 &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(), 2));
    }

    {
        // shouldn't be able to register a name you didn't preorder!
        let mut env = owned_env.get_exec_environment(Some(p2.clone()));
        assert!(is_err_code(&
                            env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "register",
                                                 &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap(), 4));
    }

    {
        // should work!
        let mut env = owned_env.get_exec_environment(Some(p1.clone()));
        assert!(is_committed(&
                             env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "register",
                                                  &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap()));
        
    }

    {
        // try to underpay!
        let mut env = owned_env.get_exec_environment(Some(p2.clone()));
        assert!(is_committed(&
                             env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "preorder",
                                                  &symbols_from_values(vec![name_hash_expensive_1.clone(), Value::Int(100)])).unwrap()));
        assert!(is_err_code(&
                            env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "register",
                                                 &symbols_from_values(vec![p2.clone(), Value::Int(2) , Value::Int(0)])).unwrap(), 4));
        
        // register a cheap name!
        assert!(is_committed(&
                             env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "preorder",
                             &symbols_from_values(vec![name_hash_cheap_0.clone(), Value::Int(100)])).unwrap()));
        assert!(is_committed(&
                             env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "register",
                             &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap()));
        
        // preorder must exist!
        assert!(is_err_code(&
                            env.execute_contract(&QualifiedContractIdentifier::local("names").unwrap(), "register",
                                                 &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap(), 5));
    }
}

fn test_simple_contract_call(owned_env: &mut OwnedEnvironment) {
    let contract_1 = FACTORIAL_CONTRACT;
    let contract_2 =
        "(define-public (proxy-compute)
            (contract-call! .factorial-contract compute 8008))
        ";

    let mut env = owned_env.get_exec_environment(Some(get_principal()));

    let contract_identifier = QualifiedContractIdentifier::local("factorial-contract").unwrap();
    env.initialize_contract(contract_identifier, contract_1).unwrap();

    let contract_identifier = QualifiedContractIdentifier::local("proxy-compute").unwrap();
    env.initialize_contract(contract_identifier, contract_2).unwrap();
    
    let args = symbols_from_values(vec![]);

    let expected = [Value::Int(5),
                    Value::Int(20),
                    Value::Int(60),
                    Value::Int(120),
                    Value::Int(120),
                    Value::Int(120)];
    for expected_result in &expected {
        env.execute_contract(&QualifiedContractIdentifier::local("proxy-compute").unwrap(), "proxy-compute", &args).unwrap();
        assert_eq!(
            env.eval_read_only(&QualifiedContractIdentifier::local("factorial-contract").unwrap(),
                               "(get current (expects! (map-get factorials (tuple (id 8008))) 'false))").unwrap(),
            *expected_result);
    }
}

fn test_aborts(owned_env: &mut OwnedEnvironment) {
    let contract_1 ="
(define-map data ((id int)) ((value int)))

;; this will return false if id != value,
;;   which _aborts_ any data that is modified during
;;   the routine.
(define-public (modify-data
                 (id int)
                 (value int))
   (begin
     (map-set! data (tuple (id id))
                      (tuple (value value)))
     (if (eq? id value)
         (ok 1)
         (err 1))))


(define-private (get-data (id int))
  (default-to 0
    (get value 
     (map-get data (tuple (id id))))))
";

    let contract_2 ="
(define-public (fail-in-other)
  (begin
    (contract-call! .contract-1 modify-data 100 101)
    (ok 1)))

(define-public (fail-in-self)
  (begin
    (contract-call! .contract-1 modify-data 105 105)
    (err 1)))
";
    let mut env = owned_env.get_exec_environment(None);

    let contract_identifier = QualifiedContractIdentifier::local("contract-1").unwrap();
    env.initialize_contract(contract_identifier, contract_1).unwrap();

    let contract_identifier = QualifiedContractIdentifier::local("contract-2").unwrap();
    env.initialize_contract(contract_identifier, contract_2).unwrap();

    env.sender = Some(get_principal());

    assert_eq!(
        env.execute_contract(&QualifiedContractIdentifier::local("contract-1").unwrap(), "modify-data",
                             &symbols_from_values(vec![Value::Int(10), Value::Int(10)])).unwrap(),
        Value::Response(ResponseData{ committed: true, data: Box::new(Value::Int(1)) }));

    assert_eq!(
        env.execute_contract(&QualifiedContractIdentifier::local("contract-1").unwrap(), "modify-data",
                             &symbols_from_values(vec![Value::Int(20), Value::Int(10)])).unwrap(),
        Value::Response(ResponseData{ committed: false, data: Box::new(Value::Int(1)) }));
    
    assert_eq!(
        env.eval_read_only(&QualifiedContractIdentifier::local("contract-1").unwrap(), 
                                                               "(get-data 20)").unwrap(),
        Value::Int(0));

    assert_eq!(
        env.eval_read_only(&QualifiedContractIdentifier::local("contract-1").unwrap(), 
                                                               "(get-data 10)").unwrap(),
        Value::Int(10));

    assert_eq!(
        env.execute_contract(&QualifiedContractIdentifier::local("contract-2").unwrap(), "fail-in-other",
                             &symbols_from_values(vec![])).unwrap(),
        Value::Response(ResponseData{ committed: true, data: Box::new(Value::Int(1)) }));

    assert_eq!(
        env.execute_contract(&QualifiedContractIdentifier::local("contract-2").unwrap(), "fail-in-self",
                             &symbols_from_values(vec![])).unwrap(),
        Value::Response(ResponseData{ committed: false, data: Box::new(Value::Int(1)) }));

    assert_eq!(
        env.eval_read_only(&QualifiedContractIdentifier::local("contract-1").unwrap(), 
                                                               "(get-data 105)").unwrap(),
        Value::Int(0));


    assert_eq!(
        env.eval_read_only(&QualifiedContractIdentifier::local("contract-1").unwrap(), 
                                                               "(get-data 100)").unwrap(),
        Value::Int(0));

    
}

fn test_factorial_contract(owned_env: &mut OwnedEnvironment) {
    let mut env = owned_env.get_exec_environment(None);

    let contract_identifier = QualifiedContractIdentifier::local("factorial").unwrap();
    env.initialize_contract(contract_identifier, FACTORIAL_CONTRACT).unwrap();

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
        
    env.sender = Some(get_principal());

    for (arguments, expectation) in arguments_to_test.iter().zip(expected.iter()) {
        env.execute_contract(&QualifiedContractIdentifier::local("factorial").unwrap(), &tx_name, arguments).unwrap();

        assert_eq!(*expectation,
                   env.eval_read_only(&QualifiedContractIdentifier::local("factorial").unwrap(),
                                      &format!("(expects! (get current (map-get factorials (tuple (id {})))) 'false)", arguments[0]))
                   .unwrap());
    }

    let err_result = env.execute_contract(&QualifiedContractIdentifier::local("factorial").unwrap(), "init-factorial",
                                          &symbols_from_values(vec![Value::Int(9000),
                                                                    Value::Int(15)])).unwrap_err();
    match err_result {
        Error::Unchecked(CheckErrors::NoSuchPublicFunction(_, _)) => {},
        _ => {
            println!("{:?}", err_result);
            panic!("Attempt to call init-factorial should fail!")
        }
    }

    let err_result = env.execute_contract(&QualifiedContractIdentifier::local("factorial").unwrap(), "compute",
                                          &symbols_from_values(vec![Value::Bool(true)])).unwrap_err();
    match err_result {
        Error::Unchecked(CheckErrors::TypeValueError(_, _)) => {},
        _ => {
            println!("{:?}", err_result);
            assert!(false, "Attempt to call compute with void type should fail!")
        }
    }

}

#[test]
fn test_all() {
    let to_test = [ test_factorial_contract,
                    test_aborts,
                    test_contract_caller,
                    test_fully_qualified_contract_call,
                    test_simple_naming_system,
                    test_simple_token_system,
                    test_simple_contract_call ];
    for test in to_test.iter() {
        with_memory_environment(test, false);
        with_marfed_environment(test, false);
    }
}
