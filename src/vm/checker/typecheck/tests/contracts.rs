use vm::parser::parse;
use vm::checker::errors::CheckErrors;
use vm::checker::{AnalysisDatabase, AnalysisDatabaseConnection};

const SIMPLE_TOKENS: &str =
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (get-balance (account principal))
            (let ((balance
                  (get balance (fetch-entry tokens (tuple (account account))))))
              (default-to 0 balance)))

         (define (token-credit! (account principal) (tokens int))
            (if (<= tokens 0)
                (err 1)
                (let ((current-amount (get-balance account)))
                  (begin
                    (set-entry! tokens (tuple (account account))
                                       (tuple (balance (+ tokens current-amount))))
                    (ok 0)))))
         (define-public (token-transfer (to principal) (amount int))
          (let ((balance (get-balance tx-sender)))
             (if (or (> amount balance) (<= amount 0))
                 (err 2)
                 (begin
                   (set-entry! tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))                     
         (begin (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10000)
                (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 300))";


const SIMPLE_NAMES: &str =
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
           (if (print (is-ok? (contract-call! tokens token-transfer
                 burn-address name-price)))
               (if
                 (insert-entry! preorder-map
                   (tuple (name-hash name-hash))
                   (tuple (paid name-price)
                          (buyer tx-sender)))
                 (ok 0) (err 2))
               (err 1)))

         (define-public (register 
                        (recipient-principal principal)
                        (name int)
                        (salt int))
           (let ((preorder-entry
                   ;; preorder entry must exist!
                   (expects (fetch-entry preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 2)))
                 (name-entry 
                   (fetch-entry name-map (tuple (name name)))))
             (if (and
                  ;; name shouldn't *already* exist
                  ;; aaron: this check actually won't even work! but the insert-entry was kicking the failure out
                  ;;              anyways...
                  ;; (eq? name-entry 'null)
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

#[test]
fn test_names_tokens_contracts() {
    use vm::checker::type_check;

    let mut tokens_contract = parse(SIMPLE_TOKENS).unwrap();
    let mut names_contract = parse(SIMPLE_NAMES).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    type_check(&"tokens", &mut tokens_contract, &mut db, true).unwrap();
    type_check(&"names", &mut names_contract, &mut db, true).unwrap();
}

#[test]
fn test_names_tokens_contracts_bad() {
    use vm::checker::type_check;
    let broken_public = "
         (define-public (broken-cross-contract (name-hash (buff 20)) (name-price int))
           (if (is-ok? (contract-call! tokens token-transfer
                 burn-address 'true))
               (begin (insert-entry! preorder-map
                 (tuple (name-hash name-hash))
                 (tuple (paid name-price)
                        (buyer tx-sender))) (ok 1))
               (err 1)))";

    let names_contract =
        format!("{}
                 {}", SIMPLE_NAMES, broken_public);

    let mut tokens_contract = parse(SIMPLE_TOKENS).unwrap();
    let mut names_contract = parse(&names_contract).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    let result = type_check(&"tokens", &mut tokens_contract, &mut db, true);
    if let Err(ref e) = result { 
        println!("{}", e);
    }
    result.unwrap();

    let err = type_check(&"names", &mut names_contract, &mut db, true).expect_err("Expected type error.");
    assert!(match &err.err {
            &CheckErrors::TypeError(ref expected_type, ref actual_type) => {
                eprintln!("Received TypeError on: {} {}", expected_type, actual_type);
                format!("{} {}", expected_type, actual_type) == "int bool"
            },
            _ => false
    });
}

#[test]
fn test_bad_map_usage() {
    use vm::checker::type_check;
    let bad_fetch = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (get-balance (account int))
            (let ((balance
                  (get balance (fetch-entry tokens (tuple (account account))))))
              balance))";
    let bad_delete = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (del-balance (account principal))
            (delete-entry! tokens (tuple (balance account))))";
    let bad_set_1 = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (set-balance (account principal))
            (set-entry! tokens (tuple (account account)) (tuple (balance \"foo\"))))";
    let bad_set_2 = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (set-balance (account principal))
            (set-entry! tokens (tuple (account \"abc\")) (tuple (balance 0))))";
    let bad_insert_1 = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (set-balance (account principal))
            (insert-entry! tokens (tuple (account account)) (tuple (balance \"foo\"))))";
    let bad_insert_2 = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (set-balance (account principal))
            (insert-entry! tokens (tuple (account \"abc\")) (tuple (balance 0))))";

    let unhandled_option =
        "(define-map tokens ((account principal)) ((balance int)))
         (define (plus-balance (account principal))
           (+ (get balance (fetch-entry tokens (tuple (account account)))) 1))";

    let tests = [bad_fetch,
                 bad_delete,
                 bad_set_1,
                 bad_set_2,
                 bad_insert_1,
                 bad_insert_2,
                 unhandled_option];

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    for contract in tests.iter() {
        let mut contract = parse(contract).unwrap();
        let result = type_check(&":transient:", &mut contract, &mut db, false);
        let err = result.expect_err("Expected a type error");
        assert!(match &err.err {
            &CheckErrors::TypeError(_,_) => true,
            _ => false
        });
    }
}


#[test]
fn test_expects() {
    use vm::checker::type_check;
    let okay = 
        "(define-map tokens ((id int)) ((balance int)))
         (define (get-balance)
            (let ((balance (expects 
                              (get balance (fetch-entry tokens (tuple (id 0)))) 
                              0)))
              (+ 0 balance)))
         (define (get-balance-2)
            (let ((balance 
                    (get balance (expects (fetch-entry tokens (tuple (id 0))) 0)) 
                              ))
              (+ 0 balance)))
          (+ (get-balance) (get-balance-2))";

    let unmatched_return_types = 
        "(define-map tokens ((id int)) ((balance int)))
         (define (get-balance)
            (let ((balance (expects 
                              (get balance (fetch-entry tokens (tuple (id 0)))) 
                              'false)))
              (+ 0 balance)))";

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    let mut okay = parse(okay).unwrap();
    let result = type_check(&":transient:", &mut okay, &mut db, false).unwrap();

    let mut unmatched_return_types = parse(unmatched_return_types).unwrap();
    let err = type_check(&":transient:", &mut unmatched_return_types, &mut db, false)
        .expect_err("Expected a type error.");
    eprintln!("unmatched_return_types returned check error: {}", err);
    assert!(match &err.err {
        &CheckErrors::ReturnTypesMustMatch => true,
        _ => false
    })
}
