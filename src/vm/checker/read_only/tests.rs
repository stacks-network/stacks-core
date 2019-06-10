use vm::parser::parse;
use vm::checker::{type_check, CheckError, CheckErrors, AnalysisDatabaseConnection};

#[test]
fn test_simple_read_only_violations() {
    // note -- these examples have _type errors_ in addition to read-only errors,
    //    but the read only error should end up taking precedence
    let bad_contracts = [ 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (let ((balance (set-entry! tokens (tuple (account tx-sender))
                                              (tuple (balance 10)))))
                 (+ 1 2)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (or (insert-entry! tokens (tuple (account tx-sender))
                                             (tuple (balance 10))) 'false))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (tuple (result (delete-entry! tokens (tuple (account tx-sender))))))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define (func1) (set-entry! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (map func1 (list 1 2 3)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define (func1) (set-entry! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (map + (list 1 (set-entry! tokens (tuple (account tx-sender)) (tuple (balance 10))) 3)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define (update-balance-and-get-tx-sender)
            (begin              
              (set-entry! tokens (tuple (account tx-sender))
                                 (tuple (balance 10)))
              tx-sender))
         (define-read-only (get-balance)
            (fetch-entry tokens ((account (update-balance-and-get-tx-sender)))))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define (update-balance-and-get-tx-sender)
            (begin              
              (set-entry! tokens (tuple (account tx-sender))
                                 (tuple (balance 10)))
              (tuple (account tx-sender))))
         (define-read-only (get-balance)
            (fetch-entry tokens (update-balance-and-get-tx-sender)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define (func1) (set-entry! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (fold func1 (list 1 2 3) 1))"];

    for contract in bad_contracts.iter() {
        let mut ast = parse(contract).unwrap();
        let mut analysis_conn = AnalysisDatabaseConnection::memory();
        let mut db = analysis_conn.begin_save_point();
        let err = type_check(&":transient:", &mut ast, &mut db, true).unwrap_err();
        assert_eq!(err.err, CheckErrors::WriteAttemptedInReadOnly)
    }
}

#[test]
fn test_contract_call_read_only_violations() {
    let contract1 = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (get-balance)
            (get balance (fetch-entry tokens (tuple (account tx-sender))) ))
         (define-public (mint)
            (begin
              (set-entry! tokens (tuple (account tx-sender))
                                              (tuple (balance 10)))
              (ok 1)))";
    let bad_caller = 
        "(define-read-only (not-reading-only)
            (contract-call! contract1 mint))";
    let ok_caller =
        "(define-read-only (is-reading-only)
            (eq? 0 (contract-call! contract1 get-balance)))";

    let mut contract1 = parse(contract1).unwrap();
    let mut bad_caller = parse(bad_caller).unwrap();
    let mut ok_caller = parse(ok_caller).unwrap();

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    type_check(&"contract1", &mut contract1, &mut db, true).unwrap();
    let err = type_check(&"bad_caller", &mut bad_caller, &mut db, true).unwrap_err();
    assert_eq!(err.err, CheckErrors::WriteAttemptedInReadOnly);

    type_check(&"ok_caller", &mut ok_caller, &mut db, true).unwrap();

}
