use assert_json_diff;
use serde_json;

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

         (define (check-balance)
           (default-to 0 
             (get balance (fetch-contract-entry
              tokens tokens (tuple (account tx-sender))))))

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
                        2)
                   (err 1) (err 3)))))

         (define-public (register 
                        (recipient-principal principal)
                        (name int)
                        (salt int))
           (let ((preorder-entry
                   ;; preorder entry must exist!
                   (expects! (fetch-entry preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 2)))
                 (name-entry 
                   (fetch-entry name-map (tuple (name name)))))
             (if (and
                  ;; name shouldn't *already* exist
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


#[test]
fn test_names_tokens_contracts_interface() {
    use vm::checker::type_check;

    const INTERFACE_TEST_CONTRACT: &str = "
        (define var1 'SP000000000000000000002Q6VF78)
        (define var2 'true)
        (define var3 45)

        (define-data-var d-var1 bool 'true)
        (define-data-var d-var2 int 2)
        (define-data-var d-var3 (buff 5) 0xdeadbeef)

        (define-map map1 ((name int)) ((owner principal)) )
        (define-map map2 ((k-name-1 bool)) ((v-name-1 (buff 33))) )
        (define-map map3 ((k-name-2 bool)) ((v-name-2 (tuple ((n1 int) (n2 bool))))) )

        (define (f00 (a1 int)) 'true)
        (define (f01 (a1 bool)) 'true)
        (define (f02 (a1 principal)) 'true)
        (define (f03 (a1 (buff 54))) 'true)
        (define (f04 (a1 (tuple ((t-name1 bool) (t-name2 int))))) 'true)
        (define (f05 (a1 (list 7 6 int))) 'true)

        (define (f06) 1)
        (define (f07) 'true)
        (define (f08) 'SP000000000000000000002Q6VF78) 
        (define (f09) 0xdeadbeef)
        (define (f10) (tuple (tn1 'true) (tn2 0) (tn3 0xff) ))
        (define (f11) (fetch-entry map1 (tuple (name 0))))
        (define (f12) (ok 3))
        (define (f13) (err 6))
        (define (f14) (if 'true (ok 1) (err 2)))
        (define (f15) (list 1 2 3))
        (define (f16) (list (list (list 5)) (list (list 55))))

        (define-public (pub-f01) (ok 1))
        (define-public (pub-f02) (ok 'true))
        (define-public (pub-f03) (err 'true))
        (define-public (pub-f04) (if 'true (ok 1) (err 2)))
        (define-public (pub-f05 (a1 int)) (ok 'true))

        (define-read-only (ro-f01) 0)
        (define-read-only (ro-f02 (a1 int)) 0)
    ";


    let mut test_contract = parse(INTERFACE_TEST_CONTRACT).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    let test_contract_json_str = type_check(&"test_contract", &mut test_contract, &mut db, true).unwrap().to_interface().serialize();
    let test_contract_json = serde_json::from_str(&test_contract_json_str).unwrap();

    let test_contract_json_expected = serde_json::from_str(r#"{
        "functions": [
            { "name": "f00",
                "access": "private",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": "bool" } 
            },
            { "name": "f01",
                "access": "private",
                "args": [{ "name": "a1", "type": "bool" }],
                "outputs": { "type": "bool" } 
            },
            { "name": "f02",
                "access": "private",
                "args": [{ "name": "a1", "type": "principal" }],
                "outputs": { "type": "bool" } 
            },
            { "name": "f03",
                "access": "private",
                "args": [{ "name": "a1", "type": { "buffer": { "length": 54 } } }],
                "outputs": { "type": "bool" } 
            },
            { "name": "f04",
                "access": "private",
                "args": [{ "name": "a1", "type": { "tuple": [
                    { "name": "t-name1", "type": "bool" },
                    { "name": "t-name2", "type": "int128" }
                ] } }],
                "outputs": { "type": "bool" } 
            },
            { "name": "f05",
                "access": "private",
                "args": [{ "name": "a1", "type": { "list": { "type": "int128", "length": 7, "dimension": 6 } } }],
                "outputs": { "type": "bool" } 
            },
            { "name": "f06",
                "access": "private",
                "args": [],
                "outputs": { "type": "int128" } 
            },
            { "name": "f07",
                "access": "private",
                "args": [],
                "outputs": { "type": "bool" } 
            },
            { "name": "f08",
                "access": "private",
                "args": [],
                "outputs": { "type": "principal" } 
            },
            { "name": "f09",
                "access": "private",
                "args": [],
                "outputs": { "type": { "buffer": { "length": 4 } } } 
            },
            { "name": "f10",
                "access": "private",
                "args": [],
                "outputs": { "type": { "tuple": [
                    { "name": "tn1", "type": "bool" },
                    { "name": "tn2", "type": "int128" },
                    { "name": "tn3", "type": { "buffer": { "length": 1 } }}
                ] } } 
            },
            { "name": "f11",
                "access": "private",
                "args": [],
                "outputs": { "type": { "optional": { "tuple": [ {
                    "name": "owner",
                    "type": "principal"
                 } ] } } } 
            },
            { "name": "f12",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "none" } } }
            },
            { "name": "f13",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "none", "error": "int128" } } }
            },
            { "name": "f14",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "int128" } } }
            },
            { "name": "f15",
                "access": "private",
                "args": [],
                "outputs": { "type": { "list": { "type": "int128", "length": 3, "dimension": 1 } } }
            },
            { "name": "f16",
                "access": "private",
                "args": [],
                "outputs": { "type": { "list": { "type": "int128", "length": 2, "dimension": 3 } } }
            },
            { "name": "pub-f01",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "none" } } }
            },
            { "name": "pub-f02",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "bool", "error": "none" } } }
            },
            { "name": "pub-f03",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "none", "error": "bool" } } }
            },
            { "name": "pub-f04",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "int128" } } }
            },
            { "name": "pub-f05",
                "access": "public",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": { "response": { "ok": "bool", "error": "none" } } }
            },
            { "name": "ro-f01",
                "access": "read_only",
                "args": [],
                "outputs": { "type": "int128" }
            },
            { "name": "ro-f02",
                "access": "read_only",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": "int128" }
            }
        ],
        "maps": [
            {
                "name": "map1",
                "key": [ {
                    "name": "name",
                    "type": "int128"
                } ],
                "value": [ {
                    "name": "owner",
                    "type": "principal"
                } ]
            },
            {
                "name": "map2",
                "key": [ {
                    "name": "k-name-1",
                    "type": "bool"
                } ],
                "value": [ {
                    "name": "v-name-1",
                    "type": {
                        "buffer": { "length": 33 }
                    }
                } ]
            },
            {
                "name": "map3",
                "key": [
                    {
                        "name": "k-name-2",
                        "type": "bool"
                    }
                ],
                "value": [ {
                    "name": "v-name-2",
                    "type": {
                        "tuple": [
                            {
                                "name": "n1",
                                "type": "int128"
                            },
                            {
                                "name": "n2",
                                "type": "bool"
                            }
                        ] }
                    }
                ]
            }
        ],
        "variables": [
            { "name": "var1", "access": "constant", "type": "principal" },
            { "name": "var2", "access": "constant", "type": "bool" },
            { "name": "var3", "access": "constant", "type": "int128" },
            { "name": "d-var1", "access": "variable", "type": "bool" },
            { "name": "d-var2", "access": "variable", "type": "int128" },
            { "name": "d-var3", "access": "variable", "type": { "buffer": { "length": 5 } } }
        ]
    }"#).unwrap();

    assert_json_eq!(test_contract_json, test_contract_json_expected);

}


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
fn test_names_tokens_contracts_bad_fetch_contract_entry() {
    use vm::checker::type_check;
    let broken_public = "
         (define (check-balance)
           (default-to 0 
             (get balance (fetch-contract-entry
              tokens tokens (tuple (accnt tx-sender)))))) ;; should be a non-admissable tuple!
    ";

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
                format!("{} {}", expected_type, actual_type) == "(tuple ((account principal))) (tuple ((accnt principal)))"
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
            (let ((balance (expects! 
                              (get balance (fetch-entry tokens (tuple (id 0)))) 
                              0)))
              (+ 0 balance)))
         (define (get-balance-2)
            (let ((balance 
                    (get balance (expects! (fetch-entry tokens (tuple (id 0))) 0)) 
                              ))
              (+ 0 balance)))
          (define (get-balance-3)
             (let ((balance
                     (expects! (get balance (fetch-entry tokens (tuple (id 0))))
                               (err 'false))))
               (ok balance)))
          (define (get-balance-4)
             (expects! (get-balance-3) 0))

          (define (t-1)
             (err 3))
          (define (get-balance-5)
             (expects-err! (t-1) 0))

          (+ (get-balance) (get-balance-2) (get-balance-5))";

    let bad_return_types_tests = [
        "(define-map tokens ((id int)) ((balance int)))
         (define (get-balance)
            (let ((balance (expects! 
                              (get balance (fetch-entry tokens (tuple (id 0)))) 
                              'false)))
              (+ 0 balance)))",
        "(define-map tokens ((id int)) ((balance int)))
         (define (get-balance)
            (let ((balance (expects! 
                              (get balance (fetch-entry tokens (tuple (id 0)))) 
                              (err 1))))
              (err 'false)))"];

    let bad_default_type = "(define-map tokens ((id int)) ((balance int)))
         (default-to 'false (get balance (fetch-entry tokens (tuple (id 0)))))";

    let notype_response_type = "
         (define (t1) (ok 3))
         (define (t2) (expects-err! (t1) 0))
    ";

    let notype_response_type_2 = "
         (define (t1) (err 3))
         (define (t2) (expects! (t1) 0))
    ";

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    let mut okay = parse(okay).unwrap();
    let result = type_check(&":transient:", &mut okay, &mut db, false).unwrap();

    for unmatched_return_types in bad_return_types_tests.iter() {
        let mut unmatched_return_types = parse(unmatched_return_types).unwrap();
        let err = type_check(&":transient:", &mut unmatched_return_types, &mut db, false)
            .expect_err("Expected a type error.");
        eprintln!("unmatched_return_types returned check error: {}", err);
        assert!(match &err.err {
            &CheckErrors::ReturnTypesMustMatch => true,
            _ => false
        })
    }

    let mut bad_default_type = parse(bad_default_type).unwrap();
    let err = type_check(&":transient:", &mut bad_default_type, &mut db, false)
        .expect_err("Expected a type error.");
    eprintln!("bad_default_types returned check error: {}", err);
    assert!(match &err.err {
        &CheckErrors::DefaultTypesMustMatch(_, _) => true,
        _ => false
    });

    let mut notype_response_type = parse(notype_response_type).unwrap();
    let err = type_check(&":transient:", &mut notype_response_type, &mut db, false)
        .expect_err("Expected a type error.");
    eprintln!("notype_response_type returned check error: {}", err);
    assert!(match &err.err {
        &CheckErrors::CouldNotDetermineResponseErrType => true,
        _ => false
    });

    let mut notype_response_type = parse(notype_response_type_2).unwrap();
    let err = type_check(&":transient:", &mut notype_response_type, &mut db, false)
        .expect_err("Expected a type error.");
    eprintln!("notype_response_type_2 returned check error: {}", err);
    assert!(match &err.err {
        &CheckErrors::CouldNotDetermineResponseOkType => true,
        _ => false
    });

}
