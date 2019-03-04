use vm::execute;
use vm::errors::{Error, ErrType};
use vm::types::{Value};
use vm::contexts::{MemoryGlobalContext, GlobalContext};
use vm::representations::SymbolicExpression;
use vm::contracts::Contract;

fn symbols_from_values(mut vec: Vec<Value>) -> Vec<SymbolicExpression> {
    vec.drain(..).map(|value| SymbolicExpression::AtomValue(value)).collect()
}

#[test]
fn test_simple_token_system() {
    let tokens_contract = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-public (get-balance (account principal))
            (let ((balance
                  (get balance (fetch-entry tokens (tuple (account account))))))
              (if (eq? balance 'null) 0 balance)))

         (define (token-credit! account tokens)
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
                (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 100)
                'null)";


    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR").unwrap();
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G").unwrap();

    let mut global_context = MemoryGlobalContext::new();

    global_context.initialize_contract("tokens", tokens_contract).unwrap();

    assert_eq!(
        global_context.execute_contract("tokens", &p2, "token-transfer",
                                        &symbols_from_values(vec![p1.clone(), Value::Int(110)])).unwrap(),
        Value::Bool(false));
    assert_eq!(
        global_context.execute_contract("tokens", &p1, "token-transfer",
                                        &symbols_from_values(vec![p2.clone(), Value::Int(9000)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        global_context.execute_contract("tokens", &p1, "token-transfer",
                                        &symbols_from_values(vec![p2.clone(), Value::Int(1001)])).unwrap(),
        Value::Bool(false));
    assert_eq!( // send to self!
        global_context.execute_contract("tokens", &p1, "token-transfer",
                                        &symbols_from_values(vec![p1.clone(), Value::Int(1000)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        global_context.execute_contract("tokens", &p1, "get-balance",
                                        &symbols_from_values(vec![p1.clone()])).unwrap(),
        Value::Int(1000));
    assert_eq!(
        global_context.execute_contract("tokens", &p1, "get-balance",
                                        &symbols_from_values(vec![p2.clone()])).unwrap(),
        Value::Int(9100));
}

#[test]
fn test_simple_naming_system() {
    let tokens_contract = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-public (get-balance (account principal))
            (let ((balance
                  (get balance (fetch-entry tokens (tuple (account account))))))
              (if (eq? balance 'null) 0 balance)))

         (define (token-credit! account tokens)
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
         (define (price-function name)
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

    let mut global_context = MemoryGlobalContext::new();

    global_context.initialize_contract("tokens", tokens_contract).unwrap();
    global_context.initialize_contract("names", names_contract).unwrap();

    assert_eq!(
        global_context.execute_contract("names", &p2, "preorder",
                                        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(),
        Value::Bool(false));
    assert_eq!(
        global_context.execute_contract("names", &p1, "preorder",
                                        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        global_context.execute_contract("names", &p1, "preorder",
                                        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap(),
        Value::Bool(false));

    // shouldn't be able to register a name you didn't preorder!
    assert_eq!(
        global_context.execute_contract("names", &p2, "register",
                                        &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap(),
        Value::Bool(false));
    // should work!
    assert_eq!(
        global_context.execute_contract("names", &p1, "register",
                                        &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap(),
        Value::Bool(true));


    // try to underpay!
    assert_eq!(
        global_context.execute_contract("names", &p2, "preorder",
                                        &symbols_from_values(vec![name_hash_expensive_1.clone(), Value::Int(100)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        global_context.execute_contract("names", &p2, "register",
                                        &symbols_from_values(vec![p2.clone(), Value::Int(2) , Value::Int(0)])).unwrap(),
        Value::Bool(false));

    // register a cheap name!
    assert_eq!(
        global_context.execute_contract("names", &p2, "preorder",
                                        &symbols_from_values(vec![name_hash_cheap_0.clone(), Value::Int(100)])).unwrap(),
        Value::Bool(true));
    assert_eq!(
        global_context.execute_contract("names", &p2, "register",
                                        &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap(),
        Value::Bool(true));
}


#[test]
fn test_simple_contract_call() {
    let contract_1 =
        "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial id factorial)
           (insert-entry! factorials (tuple (id id)) (tuple (current 1) (index factorial))))
         (define-public (compute (id int))
           (let ((entry (fetch-entry factorials (tuple (id id)))))
                (if (eq? entry 'null)
                    0
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             current
                             (begin
                               (set-entry! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               0))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5)
               'null)
        ";
    let contract_2 =
        "(define-public (proxy-compute)
            (contract-call! factorial-contract compute 8008))
        ";

    let mut global_context = MemoryGlobalContext::new();

    global_context.initialize_contract("factorial-contract", contract_1).unwrap();
    global_context.initialize_contract("proxy-compute", contract_2).unwrap();

    let args = symbols_from_values(vec![]);
    let sender = Value::Principal(1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);

    let expected = [Value::Int(0),
                    Value::Int(0),
                    Value::Int(0),
                    Value::Int(0),
                    Value::Int(120),
                    Value::Int(120)];
    for expected_result in &expected {
        assert_eq!(
            global_context.execute_contract("proxy-compute", &sender, "proxy-compute", &args).unwrap(),
            *expected_result);
    }
                                    
}

#[test]
fn test_factorial_contract() {
    let contract_defn =
        "(define-map factorials ((id int)) ((current int) (index int)))
         (define (init-factorial id factorial)
           (insert-entry! factorials (tuple (id id)) (tuple (current 1) (index factorial))))
         (define-public (compute (id int))
           (let ((entry (fetch-entry factorials (tuple (id id)))))
                (if (eq? entry 'null)
                    0
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             current
                             (begin
                               (set-entry! factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               0))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5)
               'null)
        ";


    let mut global_context = MemoryGlobalContext::new();
    let mut contract = Contract::initialize(contract_defn).unwrap();

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
        Value::Int(0),
        Value::Int(0),
        Value::Int(6),
        Value::Int(6),
        Value::Int(6),
        Value::Int(0),
        Value::Int(0),
        Value::Int(0),
        Value::Int(0),
        Value::Int(120),
        Value::Int(120),
    ];
        
    let sender = Value::Principal(1, [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]);

    arguments_to_test.iter().zip(expected.iter())
        .for_each(|(arguments, expectation)| assert_eq!(Ok(expectation.clone()),
                                                        contract.execute_transaction(
                                                            &sender,
                                                            &tx_name,
                                                            arguments,
                                                            &mut global_context)));

    let err_result = contract.execute_transaction(&sender, &"init-factorial",
                                                  &symbols_from_values(vec![Value::Int(9000),
                                                                            Value::Int(15)]),
                                                  &mut global_context);
    match err_result {
        Err(Error{
            err_type: ErrType::NonPublicFunction(_),
            stack_trace: _ }) => {},
        _ => {
            println!("{:?}", err_result);
            panic!("Attempt to call init-factorial should fail!")
        }
    }

    let err_result = contract.execute_transaction(&Value::Void, &"compute",
                                                  &symbols_from_values(vec![Value::Int(1337)]),
                                                  &mut global_context);
    match err_result {
        Err(Error{
            err_type: ErrType::BadSender(_),
            stack_trace: _ }) => {},
        _ => {
            println!("{:?}", err_result);
            assert!(false, "Attempt to call with bad sender should fail!")
        }
    }

    let err_result = contract.execute_transaction(&sender, &"compute",
                                                  &symbols_from_values(vec![Value::Void]),
                                                  &mut global_context);
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
