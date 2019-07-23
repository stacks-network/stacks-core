use vm::execute as vm_execute;
use vm::errors::{Error, UncheckedError, RuntimeErrorType};
use vm::types::{Value, PrincipalData, ResponseData, AssetIdentifier};
use vm::contexts::{OwnedEnvironment, GlobalContext, AssetMap, AssetMapEntry};
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
         (define-read-only (my-get-balance (account principal))
            (get-balance stackaroos account))
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

         (define-public (force-mint (name int))
           (mint-asset! names name tx-sender))
         (define-public (try-bad-transfers)
           (begin
             (contract-call! tokens my-token-transfer burn-address 50000)
             (contract-call! tokens my-token-transfer burn-address 1000)
             (contract-call! tokens my-token-transfer burn-address 1)
             (err 0)))
         (define-public (try-bad-transfers-but-ok)
           (begin
             (contract-call! tokens my-token-transfer burn-address 50000)
             (contract-call! tokens my-token-transfer burn-address 1000)
             (contract-call! tokens my-token-transfer burn-address 1)
             (ok 0)))
         (define-public (transfer (name int) (recipient principal))
           (let ((transfer-name-result (transfer-asset! names name tx-sender recipient))
                 (token-to-contract-result (contract-call! tokens my-token-transfer 'CTnames 1))
                 (contract-to-burn-result (as-contract (contract-call! tokens my-token-transfer burn-address 1))))
             (begin (expects! transfer-name-result transfer-name-result)
                    (expects! token-to-contract-result token-to-contract-result)
                    (expects! contract-to-burn-result contract-to-burn-result)
                    (ok 0))))
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
    eprintln!("is_committed?: {}", v);

    match v {
        Value::Response(ref data) => data.committed,
        _ => false
    }
}

fn is_err_code(v: &Value, e: i128) -> bool {
    eprintln!("is_err_code?: {}", v);
    match v {
        Value::Response(ref data) => {
            !data.committed &&
                *data.data == Value::Int(e)
        },
        _ => false
    }
}

fn execute_transaction(conn: &mut ContractDatabaseConnection, sender: Value, contract: &str,
                       tx: &str, args: &[SymbolicExpression]) -> Result<(Value, AssetMap), Error> {
    let owned_env = OwnedEnvironment::new(conn);
    owned_env.execute_transaction(sender, contract, tx, args)
}

#[test]
fn test_simple_token_system() {
    let tokens_contract = FIRST_CLASS_TOKENS;

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let p1_principal = match p1 {
        Value::Principal(ref data) => data.clone(),
        _ => panic!()
    };

    let p2_principal = match p2 {
        Value::Principal(ref data) => data.clone(),
        _ => panic!()
    };

    let token_identifier = AssetIdentifier { contract_name: "tokens".to_string(),
                                             asset_name: "stackaroos".to_string() };

    let contract_principal = PrincipalData::ContractPrincipal("tokens".to_string());

    let mut conn = ContractDatabaseConnection::memory().unwrap();

    {
        let owned_env = OwnedEnvironment::new(&mut conn);
        owned_env.initialize_contract("tokens", tokens_contract).unwrap();
    }

    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "tokens", "my-token-transfer",
        &symbols_from_values(vec![p1.clone(), Value::Int(210)])).unwrap();
    assert!(!is_committed(&result));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "my-token-transfer",
        &symbols_from_values(vec![p2.clone(), Value::Int(9000)])).unwrap();
    
    assert!(is_committed(&result));

    let asset_map = asset_map.to_table();
    assert_eq!(asset_map[&p1_principal][&token_identifier], AssetMapEntry::Token(9000));

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "my-token-transfer",
        &symbols_from_values(vec![p2.clone(), Value::Int(1001)])).unwrap();

    assert!(is_err_code(&result, 1));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "my-token-transfer",
        &symbols_from_values(vec![p1.clone(), Value::Int(1000)])).unwrap();

    assert!(is_err_code(&result, 2));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "my-token-transfer",
        &symbols_from_values(vec![p1.clone(), Value::Int(-1)])).unwrap();

    assert!(is_err_code(&result, 3));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "my-get-balance", &symbols_from_values(vec![p1.clone()])).unwrap();

    assert_eq!(
        result,
        Value::Int(1000));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "my-get-balance", &symbols_from_values(vec![p2.clone()])).unwrap();

    assert_eq!(
        result,
        Value::Int(9200));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "faucet", &vec![]).unwrap();

    assert!(is_committed(&result));

    let asset_map = asset_map.to_table();
    assert_eq!(asset_map[&contract_principal][&token_identifier], AssetMapEntry::Token(1));

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "faucet", &vec![]).unwrap();

    let asset_map = asset_map.to_table();
    assert!(is_committed(&result));
    assert_eq!(asset_map[&contract_principal][&token_identifier], AssetMapEntry::Token(1));

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "faucet", &vec![]).unwrap();

    let asset_map = asset_map.to_table();
    assert!(is_committed(&result));
    assert_eq!(asset_map[&contract_principal][&token_identifier], AssetMapEntry::Token(1));

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "my-get-balance", &symbols_from_values(vec![p1.clone()])).unwrap();

    assert_eq!(
        result,
        Value::Int(1003));

    let (result, asset_map) = execute_transaction(&mut conn,
        p1.clone(), "tokens", "mint-after", &symbols_from_values(vec![Value::Int(25)])).unwrap();

    assert!(!is_committed(&result));
    assert_eq!(asset_map.to_table().len(), 0);
    
}

#[test]
fn test_simple_naming_system() {
    let tokens_contract = FIRST_CLASS_TOKENS;

    let names_contract = ASSET_NAMES;

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let p1_principal = match p1 {
        Value::Principal(ref data) => data.clone(),
        _ => panic!()
    };

    let p2_principal = match p2 {
        Value::Principal(ref data) => data.clone(),
        _ => panic!()
    };

    let names_identifier = AssetIdentifier { contract_name: "names".to_string(),
                                             asset_name: "names".to_string() };
    let tokens_identifier = AssetIdentifier { contract_name: "tokens".to_string(),
                                             asset_name: "stackaroos".to_string() };


    let name_hash_expensive_0 = execute("(hash160 1)");
    let name_hash_expensive_1 = execute("(hash160 2)");
    let name_hash_cheap_0 = execute("(hash160 100001)");

    let mut conn = ContractDatabaseConnection::memory().unwrap();

    {
        let owned_env = OwnedEnvironment::new(&mut conn);
        owned_env.initialize_contract("tokens", tokens_contract).unwrap();
    }

    {
        let owned_env = OwnedEnvironment::new(&mut conn);
        owned_env.initialize_contract("names", names_contract).unwrap();
    }

    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "names", "preorder",
        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap();

    assert!(is_err_code(&result, 1));
    
    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "preorder",
        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap();
    
    assert!(is_committed(&result));
    
    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "preorder",
        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap();

    assert!(is_err_code(&result, 2));


    // shouldn't be able to register a name you didn't preorder!


    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "names", "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap();

    assert!(is_err_code(&result, 4));

    // should work!

    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap();
            
    assert!(is_committed(&result));
    

    {
        let mut owned_env = OwnedEnvironment::new(&mut conn);
        let mut env = owned_env.get_exec_environment(None);
        assert_eq!(
            env.eval_read_only("names",
                               "(get-owner names 1)").unwrap(),
            Value::some(p2.clone()));
    }

    // let's try some token-transfers

    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "try-bad-transfers", &vec![]).unwrap();
    assert!(is_err_code(&result, 0));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "try-bad-transfers-but-ok", &vec![]).unwrap();

    assert!(is_committed(&result));

    let asset_map = asset_map.to_table();
    assert_eq!(asset_map[&p1_principal][&tokens_identifier], AssetMapEntry::Token(1001));

    // let's mint some names

    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "force-mint", 
        &symbols_from_values(vec![Value::Int(1)])).unwrap();

    assert!(is_err_code(&result, 1));
    assert_eq!(asset_map.to_table().len(), 0);


    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "force-mint", 
        &symbols_from_values(vec![Value::Int(5)])).unwrap();

    assert!(is_committed(&result));
    assert_eq!(asset_map.to_table().len(), 0);

    // let's transfer name


    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "transfer", 
        &symbols_from_values(vec![Value::Int(7), p2.clone()])).unwrap();

    assert!(is_err_code(&result, 3));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "transfer", 
        &symbols_from_values(vec![Value::Int(1), p2.clone()])).unwrap();

    assert!(is_err_code(&result, 1));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "names", "transfer", 
        &symbols_from_values(vec![Value::Int(1), p2.clone()])).unwrap();

    assert!(is_err_code(&result, 2));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(
        &mut conn, p1.clone(), "names", "transfer", 
        &symbols_from_values(vec![Value::Int(5), p2.clone()])).unwrap();

    println!("{}", asset_map);
    let asset_map = asset_map.to_table();

    assert!(is_committed(&result));
    assert_eq!(asset_map[&p1_principal][&names_identifier], AssetMapEntry::Asset(vec![Value::Int(5)]));
    assert_eq!(asset_map[&p1_principal][&tokens_identifier], AssetMapEntry::Token(1));

    // try to underpay!

    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "names", "preorder",
        &symbols_from_values(vec![name_hash_expensive_1.clone(), Value::Int(100)])).unwrap();

    assert!(is_committed(&result));
    
    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "names", "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(2) , Value::Int(0)])).unwrap();

    assert!(is_err_code(&result, 4));
    
    // register a cheap name!

    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "names", "preorder",
        &symbols_from_values(vec![name_hash_cheap_0.clone(), Value::Int(100)])).unwrap();

    assert!(is_committed(&result));


    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "names", "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap();

    assert!(is_committed(&result));
    

    let (result, asset_map) = execute_transaction(
        &mut conn, p2.clone(), "names", "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap();

    // preorder must exist!
    assert!(is_err_code(&result, 5));
}
