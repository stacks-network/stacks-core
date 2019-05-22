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
