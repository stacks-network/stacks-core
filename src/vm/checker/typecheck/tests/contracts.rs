use vm::parser::parse;
use vm::checker::errors::CheckErrors;
use vm::checker::{AnalysisDatabase, AnalysisDatabaseConnection};

#[test]
fn test_names_tokens_contracts() {
    use vm::checker::type_check;
    let tokens_contract = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (get-balance (account principal))
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

         (define-read-only (get-balance)
           (contract-call! tokens get-balance tx-sender))
         
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

    let mut tokens_contract = parse(tokens_contract).unwrap();
    let mut names_contract = parse(names_contract).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    type_check(&"tokens", &mut tokens_contract, &mut db, true).unwrap();
    type_check(&"names", &mut names_contract, &mut db, true).unwrap();
}

#[test]
fn test_names_tokens_contracts_2() {
    use vm::checker::type_check;
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
                 burn-address 'true)
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

    let mut tokens_contract = parse(tokens_contract).unwrap();
    let mut names_contract = parse(names_contract).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    let result = type_check(&"tokens", &mut tokens_contract, &mut db, true);
    if let Err(ref e) = result { 
        println!("{}", e);
    }
    result.unwrap();

    let result = type_check(&"names", &mut names_contract, &mut db, true);
    if let Err(ref e) = result { 
        println!("{}", e);
    } else {
        panic!();
    }
}

#[test]
fn test_bad_map_usage() {
    use vm::checker::type_check;
    let bad_fetch = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define (get-balance (account int))
            (let ((balance
                  (get balance (fetch-entry tokens (tuple (account account))))))
              (if (eq? balance 'null) 0 balance)))";
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

    let tests = [bad_fetch,
                 bad_delete,
                 bad_set_1,
                 bad_set_2,
                 bad_insert_1,
                 bad_insert_2];

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    for contract in tests.iter() {
        let mut contract = parse(contract).unwrap();
        let result = type_check(&"transient", &mut contract, &mut db, false);
        let err = result.expect_err("Expected a type error");
        assert!(match &err.err {
            &CheckErrors::TypeError(_,_) => true,
            _ => false
        });
    }
}
