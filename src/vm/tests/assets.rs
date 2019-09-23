use vm::execute as vm_execute;
use vm::errors::{Error, CheckErrors, RuntimeErrorType};
use vm::types::{Value, PrincipalData, ResponseData, QualifiedContractIdentifier, AssetIdentifier};
use vm::contexts::{OwnedEnvironment, GlobalContext, AssetMap, AssetMapEntry};
use vm::representations::SymbolicExpression;
use vm::contracts::Contract;
use util::hash::hex_bytes;
use vm::tests::{with_memory_environment, with_marfed_environment, symbols_from_values,
                execute, is_err_code, is_committed};

const FIRST_CLASS_TOKENS: &str = "(define-fungible-token stackaroos)
         (define-read-only (my-ft-get-balance (account principal))
            (ft-get-balance stackaroos account))
         (define-public (my-token-transfer (to principal) (amount int))
            (ft-transfer! stackaroos amount tx-sender to))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (ft-transfer! stackaroos 1 tx-sender original-sender))))
         (define-public (mint-after (block-to-release int))
           (if (>= block-height block-to-release)
               (faucet)
               (err \"must be in the future\")))
         (begin (ft-mint! stackaroos 10000 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
                (ft-mint! stackaroos 200 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
                (ft-mint! stackaroos 4 .tokens))";

const ASSET_NAMES: &str =
        "(define-constant burn-address 'SP000000000000000000002Q6VF78)
         (define-private (price-function (name int))
           (if (< name 100000) 1000 100))
         
         (define-non-fungible-token names int)
         (define-map preorder-map
           ((name-hash (buff 20)))
           ((buyer principal) (paid int)))
         
         (define-public (preorder 
                        (name-hash (buff 20))
                        (name-price int))
           (let ((xfer-result (contract-call! .tokens my-token-transfer
                                burn-address name-price)))
            (if (is-ok? xfer-result)
               (if
                 (map-insert! preorder-map
                   (tuple (name-hash name-hash))
                   (tuple (paid name-price)
                          (buyer tx-sender)))
                 (ok 0) (err 2))
               (if (eq? xfer-result (err 1)) ;; not enough balance
                   (err 1) (err 3)))))

         (define-public (force-mint (name int))
           (nft-mint! names name tx-sender))
         (define-public (try-bad-transfers)
           (begin
             (contract-call! .tokens my-token-transfer burn-address 50000)
             (contract-call! .tokens my-token-transfer burn-address 1000)
             (contract-call! .tokens my-token-transfer burn-address 1)
             (err 0)))
         (define-public (try-bad-transfers-but-ok)
           (begin
             (contract-call! .tokens my-token-transfer burn-address 50000)
             (contract-call! .tokens my-token-transfer burn-address 1000)
             (contract-call! .tokens my-token-transfer burn-address 1)
             (ok 0)))
         (define-public (transfer (name int) (recipient principal))
           (let ((transfer-name-result (nft-transfer! names name tx-sender recipient))
                 (token-to-contract-result (contract-call! .tokens my-token-transfer .names 1))
                 (contract-to-burn-result (as-contract (contract-call! .tokens my-token-transfer burn-address 1))))
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
                   (expects! (map-get preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 5)))
                 (name-entry 
                   (nft-get-owner names name)))
             (if (and
                  (is-none? name-entry)
                  ;; preorder must have paid enough
                  (<= (price-function name) 
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (eq? tx-sender
                       (get buyer preorder-entry)))
                  (if (and
                    (is-ok? (nft-mint! names name recipient-principal))
                    (map-delete! preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                    (ok 0)
                    (err 3))
                  (err 4))))";

fn execute_transaction(env: &mut OwnedEnvironment, issuer: Value, contract_identifier: &QualifiedContractIdentifier,
                       tx: &str, args: &[SymbolicExpression]) -> Result<(Value, AssetMap), Error> {
    env.execute_transaction(issuer, contract_identifier.clone(), tx, args)
}

fn test_simple_token_system(owned_env: &mut OwnedEnvironment) {
    let tokens_contract = FIRST_CLASS_TOKENS;

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let p1_principal = match p1 {
        Value::Principal(PrincipalData::Standard(ref data)) => data.clone(),
        _ => panic!()
    };

    let p2_principal = match p2 {
        Value::Principal(ref data) => data.clone(),
        _ => panic!()
    };

    let token_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "tokens".into());

    let token_identifier = AssetIdentifier { contract_identifier: token_contract_id.clone(),
                                             asset_name: "stackaroos".into() };

    let contract_principal = PrincipalData::Contract(token_contract_id.clone());

    owned_env.initialize_contract(token_contract_id.clone(), tokens_contract).unwrap();

    let (result, asset_map) = execute_transaction(owned_env, 
        p2.clone(), &token_contract_id.clone(), "my-token-transfer",
        &symbols_from_values(vec![p1.clone(), Value::Int(210)])).unwrap();
    assert!(!is_committed(&result));

    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "my-token-transfer",
        &symbols_from_values(vec![p2.clone(), Value::Int(9000)])).unwrap();
    assert!(is_committed(&result));

    let asset_map = asset_map.to_table();
    assert_eq!(asset_map[&PrincipalData::Standard(p1_principal)][&token_identifier], AssetMapEntry::Token(9000));

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "my-token-transfer",
        &symbols_from_values(vec![p2.clone(), Value::Int(1001)])).unwrap();

    assert!(is_err_code(&result, 1));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "my-token-transfer",
        &symbols_from_values(vec![p1.clone(), Value::Int(1000)])).unwrap();

    assert!(is_err_code(&result, 2));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "my-token-transfer",
        &symbols_from_values(vec![p1.clone(), Value::Int(-1)])).unwrap();

    assert!(is_err_code(&result, 3));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "my-ft-get-balance", &symbols_from_values(vec![p1.clone()])).unwrap();

    assert_eq!(
        result,
        Value::Int(1000));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "my-ft-get-balance", &symbols_from_values(vec![p2.clone()])).unwrap();

    assert_eq!(
        result,
        Value::Int(9200));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "faucet", &vec![]).unwrap();

    assert!(is_committed(&result));

    let asset_map = asset_map.to_table();
    assert_eq!(asset_map[&contract_principal][&token_identifier], AssetMapEntry::Token(1));

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "faucet", &vec![]).unwrap();

    let asset_map = asset_map.to_table();
    assert!(is_committed(&result));
    assert_eq!(asset_map[&contract_principal][&token_identifier], AssetMapEntry::Token(1));

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "faucet", &vec![]).unwrap();

    let asset_map = asset_map.to_table();
    assert!(is_committed(&result));
    assert_eq!(asset_map[&contract_principal][&token_identifier], AssetMapEntry::Token(1));

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "my-ft-get-balance", &symbols_from_values(vec![p1.clone()])).unwrap();

    assert_eq!(
        result,
        Value::Int(1003));

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "mint-after", &symbols_from_values(vec![Value::Int(25)])).unwrap();

    assert!(!is_committed(&result));
    assert_eq!(asset_map.to_table().len(), 0);
    
}

fn total_supply(owned_env: &mut OwnedEnvironment) {
    let bad_0 = "(define-fungible-token stackaroos (- 5))";
    let bad_1 = "(define-fungible-token stackaroos 'true)";

    let contract = "(define-fungible-token stackaroos 5)
         (define-read-only (get-balance (account principal))
            (ft-get-balance stackaroos account))
         (define-public (transfer (to principal) (amount int))
            (ft-transfer! stackaroos amount tx-sender to))
         (define-public (faucet)
            (ft-mint! stackaroos 2 tx-sender))
         (define-public (gated-faucet (x bool))
            (begin (faucet)
                   (if x (ok 1) (err 0))))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    
    let p1_principal = match p1 {
        Value::Principal(PrincipalData::Standard(ref data)) => data.clone(),
        _ => panic!()
    };

    let token_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "tokens".into());
    let err = owned_env.initialize_contract(token_contract_id.clone(), bad_0).unwrap_err();
    assert!( match err {
        Error::Runtime(RuntimeErrorType::NonPositiveTokenSupply, _) => true,
        _ => false
    });

    let err = owned_env.initialize_contract(token_contract_id.clone(), bad_1).unwrap_err();
    assert!( match err {
        Error::Unchecked(CheckErrors::TypeValueError(_, _)) => true,
        _ => false
    });

    owned_env.initialize_contract(token_contract_id.clone(), contract).unwrap();

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "gated-faucet",
        &symbols_from_values(vec![Value::Bool(true)])).unwrap();
    assert!(is_committed(&result));

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "gated-faucet",
        &symbols_from_values(vec![Value::Bool(false)])).unwrap();
    assert!(!is_committed(&result));

    let (result, asset_map) = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "gated-faucet",
        &symbols_from_values(vec![Value::Bool(true)])).unwrap();
    assert!(is_committed(&result));

    let err = execute_transaction(owned_env,
        p1.clone(), &token_contract_id.clone(), "gated-faucet",
        &symbols_from_values(vec![Value::Bool(false)])).unwrap_err();
    println!("{}", err);
    assert!( match err {
        Error::Runtime(RuntimeErrorType::SupplyOverflow(x, y), _) => (x, y) == (6, 5),
        _ => false
    });
}

fn test_simple_naming_system(owned_env: &mut OwnedEnvironment) {
    let tokens_contract = FIRST_CLASS_TOKENS;

    let names_contract = ASSET_NAMES;

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let p1_principal = match p1 {
        Value::Principal(PrincipalData::Standard(ref data)) => data.clone(),
        _ => panic!()
    };

    let p2_principal = match p2 {
        Value::Principal(ref data) => data.clone(),
        _ => panic!()
    };

    let tokens_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "tokens".into());

    let names_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "names".into());

    let names_identifier = AssetIdentifier { contract_identifier: names_contract_id.clone(),
                                             asset_name: "names".into() };
    let tokens_identifier = AssetIdentifier { contract_identifier: tokens_contract_id.clone(),
                                             asset_name: "stackaroos".into() };


    let name_hash_expensive_0 = execute("(hash160 1)");
    let name_hash_expensive_1 = execute("(hash160 2)");
    let name_hash_cheap_0 = execute("(hash160 100001)");

    owned_env.initialize_contract(tokens_contract_id.clone(), tokens_contract).unwrap();

    let names_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "names".into());
    owned_env.initialize_contract(names_contract_id.clone(), names_contract).unwrap();

    let (result, asset_map) = execute_transaction(
        owned_env, p2.clone(), &names_contract_id, "preorder",
        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap();

    assert!(is_err_code(&result, 1));
    
    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "preorder",
        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap();
    
    assert!(is_committed(&result));
    
    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "preorder",
        &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::Int(1000)])).unwrap();

    assert!(is_err_code(&result, 2));


    // shouldn't be able to register a name you didn't preorder!


    let (result, asset_map) = execute_transaction(
        owned_env, p2.clone(), &names_contract_id, "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap();

    assert!(is_err_code(&result, 4));

    // should work!

    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(1) , Value::Int(0)])).unwrap();
            
    assert!(is_committed(&result));
    

    {
        let mut env = owned_env.get_exec_environment(None);
        assert_eq!(
            env.eval_read_only(&tokens_contract_id.clone(),
                               "(nft-get-owner names 1)").unwrap(),
            Value::some(p2.clone()));
    }

    // let's try some token-transfers

    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "try-bad-transfers", &vec![]).unwrap();
    assert!(is_err_code(&result, 0));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "try-bad-transfers-but-ok", &vec![]).unwrap();

    assert!(is_committed(&result));

    let asset_map = asset_map.to_table();
    assert_eq!(asset_map[&PrincipalData::Standard(p1_principal.clone())][&tokens_identifier], AssetMapEntry::Token(1001));

    // let's mint some names

    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "force-mint", 
        &symbols_from_values(vec![Value::Int(1)])).unwrap();

    assert!(is_err_code(&result, 1));
    assert_eq!(asset_map.to_table().len(), 0);


    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "force-mint", 
        &symbols_from_values(vec![Value::Int(5)])).unwrap();

    assert!(is_committed(&result));
    assert_eq!(asset_map.to_table().len(), 0);

    // let's transfer name


    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "transfer", 
        &symbols_from_values(vec![Value::Int(7), p2.clone()])).unwrap();

    assert!(is_err_code(&result, 3));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "transfer", 
        &symbols_from_values(vec![Value::Int(1), p2.clone()])).unwrap();

    assert!(is_err_code(&result, 1));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(
        owned_env, p2.clone(), &names_contract_id, "transfer", 
        &symbols_from_values(vec![Value::Int(1), p2.clone()])).unwrap();

    assert!(is_err_code(&result, 2));
    assert_eq!(asset_map.to_table().len(), 0);

    let (result, asset_map) = execute_transaction(
        owned_env, p1.clone(), &names_contract_id, "transfer", 
        &symbols_from_values(vec![Value::Int(5), p2.clone()])).unwrap();

    println!("{}", asset_map);
    let asset_map = asset_map.to_table();

    assert!(is_committed(&result));
    assert_eq!(asset_map[&PrincipalData::Standard(p1_principal.clone())][&names_identifier], AssetMapEntry::Asset(vec![Value::Int(5)]));
    assert_eq!(asset_map[&PrincipalData::Standard(p1_principal)][&tokens_identifier], AssetMapEntry::Token(1));

    // try to underpay!

    let (result, asset_map) = execute_transaction(
        owned_env, p2.clone(), &names_contract_id, "preorder",
        &symbols_from_values(vec![name_hash_expensive_1.clone(), Value::Int(100)])).unwrap();

    assert!(is_committed(&result));
    
    let (result, asset_map) = execute_transaction(
        owned_env, p2.clone(), &names_contract_id, "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(2) , Value::Int(0)])).unwrap();

    assert!(is_err_code(&result, 4));
    
    // register a cheap name!

    let (result, asset_map) = execute_transaction(
        owned_env, p2.clone(), &names_contract_id, "preorder",
        &symbols_from_values(vec![name_hash_cheap_0.clone(), Value::Int(100)])).unwrap();

    assert!(is_committed(&result));


    let (result, asset_map) = execute_transaction(
        owned_env, p2.clone(), &names_contract_id, "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap();

    assert!(is_committed(&result));
    

    let (result, asset_map) = execute_transaction(
        owned_env, p2.clone(), &names_contract_id, "register",
        &symbols_from_values(vec![p2.clone(), Value::Int(100001) , Value::Int(0)])).unwrap();

    // preorder must exist!
    assert!(is_err_code(&result, 5));
}


#[test]
fn test_all() {
    // let to_test = [test_simple_token_system, test_simple_naming_system, total_supply];
    let to_test = [test_simple_token_system, total_supply];
    for test in to_test.iter() {
        with_memory_environment(test, true);
        with_marfed_environment(test, true);
    }
}
