use vm::ast::parse;
use vm::analysis::{type_check, mem_type_check, CheckError, CheckErrors, AnalysisDatabase};
use vm::types::QualifiedContractIdentifier;

#[test]
fn test_at_block_violations() {
    let examples = [
        "(define-data-var foo int 1)
         (define-private (foo-bar)
           (at-block (sha256 0)
             (var-set! foo 0)))",
        // make sure that short-circuit evaluation isn't happening.
        // i.e., once (foo-bar) is known to be writing, `(at-block ..)` 
        //  should trigger an error.
        "(define-data-var foo int 1)
         (define-private (foo-bar)
           (+ (begin (var-set! foo 2) (var-get foo))
              (begin (at-block (sha256 0) (var-set! foo 0)) (var-get foo))))",
        "(define-data-var foo int 1)
         (+ (begin (var-set! foo 2) (var-get foo))
            (begin (at-block (sha256 0) (var-set! foo 0)) (var-get foo)))",
        "(define-data-var foo int 1)
         (define-fungible-token bar (begin (at-block (sha256 0) (var-set! foo 0)) 1))",
    ];

    for contract in examples.iter() {
        let err = mem_type_check(contract).unwrap_err();
        eprintln!("{}", err);
        assert_eq!(err.err, CheckErrors::AtBlockClosureMustBeReadOnly)
    }

}

#[test]
fn test_simple_read_only_violations() {
    // note -- these examples have _type errors_ in addition to read-only errors,
    //    but the read only error should end up taking precedence
    let bad_contracts = [ 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (let ((balance (map-set! tokens (tuple (account tx-sender))
                                              (tuple (balance 10)))))
                 (+ 1 2)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (or (map-insert! tokens (tuple (account tx-sender))
                                             (tuple (balance 10))) 'false))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (tuple (result (map-delete! tokens (tuple (account tx-sender))))))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (map func1 (list 1 2 3)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (map + (list 1 (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))) 3)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (update-balance-and-get-tx-sender)
            (begin              
              (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10)))
              tx-sender))
         (define-read-only (get-token-balance)
            (map-get tokens ((account (update-balance-and-get-tx-sender)))))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (update-balance-and-get-tx-sender)
            (begin              
              (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10)))
              (tuple (account tx-sender))))
         (define-read-only (get-token-balance)
            (map-get tokens (update-balance-and-get-tx-sender)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (update-balance-and-get-tx-sender)
            (begin              
              (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10)))
              tx-sender))
         (define-read-only (get-token-balance)
            (map-get tokens ((account (update-balance-and-get-tx-sender)))))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (let ((x 1))
              (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10)))
              x))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (fold func1 (list 1 2 3) 1))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (asserts! (map-insert! tokens (tuple (account tx-sender))
                                             (tuple (balance 10))) 'false))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (begin (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (len (func1)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (begin (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (append (func1) 3))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (begin (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (concat (func1) (func1)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (begin (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (asserts-max-len (func1) 3))"];

    for contract in bad_contracts.iter() {
        let err = mem_type_check(contract).unwrap_err();
        assert_eq!(err.err, CheckErrors::WriteAttemptedInReadOnly)
    }
}

#[test]
fn test_contract_call_read_only_violations() {
    let contract1 = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (get-token-balance)
            (get balance (map-get tokens (tuple (account tx-sender))) ))
         (define-public (mint)
            (begin
              (map-set! tokens (tuple (account tx-sender))
                                              (tuple (balance 10)))
              (ok 1)))";
    let bad_caller = 
        "(define-read-only (not-reading-only)
            (contract-call! .contract1 mint))";
    let ok_caller =
        "(define-read-only (is-reading-only)
            (eq? 0 (expects! (contract-call! .contract1 get-token-balance) 'false)))";

    let contract_1_id = QualifiedContractIdentifier::local("contract1").unwrap();
    let contract_bad_caller_id = QualifiedContractIdentifier::local("bad_caller").unwrap();
    let contract_ok_caller_id = QualifiedContractIdentifier::local("ok_caller").unwrap();

    let mut contract1 = parse(&contract_1_id, contract1).unwrap();
    let mut bad_caller = parse(&contract_bad_caller_id, bad_caller).unwrap();
    let mut ok_caller = parse(&contract_ok_caller_id, ok_caller).unwrap();

    let mut db = AnalysisDatabase::memory();
    db.execute(|db| type_check(&contract_1_id, &mut contract1, db, true)).unwrap();

    let err = db.execute(|db| type_check(&contract_bad_caller_id, &mut bad_caller, db, true)).unwrap_err();
    assert_eq!(err.err, CheckErrors::WriteAttemptedInReadOnly);

    db.execute(|db| type_check(&contract_ok_caller_id, &mut ok_caller, db, true)).unwrap();

}
