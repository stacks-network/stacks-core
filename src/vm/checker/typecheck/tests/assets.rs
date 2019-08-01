use vm::types::AtomTypeIdentifier;
use vm::parser::parse;
use vm::checker::errors::CheckErrors;
use vm::checker::{AnalysisDatabase, AnalysisDatabaseConnection};

const FIRST_CLASS_TOKENS: &str = "(define-token stackaroos)
         (define-asset stacka-nfts (buff 10))
         (get-asset-owner stacka-nfts \"1234567890\" )
         (define-read-only (my-get-token-balance (account principal))
            (get-token-balance stackaroos account))
         (define-public (my-token-transfer (to principal) (amount int))
            (transfer-token! stackaroos amount tx-sender to))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (transfer-token! stackaroos 1 tx-sender original-sender))))
         (define-public (mint-after (block-to-release int))
           (if (>= block-height block-to-release)
               (faucet)
               (err 8)))
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

         (define-public (register 
                        (recipient-principal principal)
                        (name int)
                        (salt int))
           (let ((preorder-entry
                   ;; preorder entry must exist!
                   (expects! (fetch-entry preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 5)))
                 (name-entry 
                   (get-asset-owner names name)))
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

#[test]
fn test_names_tokens_contracts() {
    use vm::checker::type_check;

    let mut tokens_contract = parse(FIRST_CLASS_TOKENS).unwrap();
    let mut names_contract = parse(ASSET_NAMES).unwrap();
    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();

    type_check(&"tokens", &mut tokens_contract, &mut db, true).unwrap();
    type_check(&"names", &mut names_contract, &mut db, true).unwrap();
}


#[test]
fn test_bad_asset_usage() {
    use vm::checker::type_check;

    let bad_scripts = ["(get-token-balance stackoos tx-sender)",
                       "(get-token-balance 1234 tx-sender)",
                       "(get-token-balance stackaroos 100)",
                       "(get-asset-owner 1234 \"abc\")",
                       "(get-asset-owner stackoos \"abc\")",
                       "(get-asset-owner stacka-nfts 1234 )",
                       "(get-asset-owner stacka-nfts \"123456789012345\" )",
                       "(mint-asset! 1234 \"abc\" tx-sender)",
                       "(mint-asset! stackoos \"abc\" tx-sender)",
                       "(mint-asset! stacka-nfts 1234 tx-sender)",
                       "(mint-asset! stacka-nfts \"123456789012345\" tx-sender)",
                       "(mint-asset! stacka-nfts \"abc\" 2)",
                       "(mint-token! stackoos 1 tx-sender)",
                       "(mint-token! 1234 1 tx-sender)",
                       "(mint-token! stackaroos 2 100)",
                       "(mint-token! stackaroos 'true tx-sender)",
                       "(transfer-asset! 1234 \"a\" tx-sender tx-sender)",
                       "(transfer-asset! stackoos    \"a\" tx-sender tx-sender)",
                       "(transfer-asset! stacka-nfts \"a\" 2 tx-sender)",
                       "(transfer-asset! stacka-nfts \"a\" tx-sender 2)",
                       "(transfer-asset! stacka-nfts 2 tx-sender tx-sender)",
                       "(transfer-token! stackoos 1 tx-sender tx-sender)",
                       "(transfer-token! 1234 1 tx-sender tx-sender)",
                       "(transfer-token! stackaroos 2 100 tx-sender)",
                       "(transfer-token! stackaroos 'true tx-sender tx-sender)",
                       "(transfer-token! stackaroos 2 tx-sender 100)",
    ];

    let expected = [
        CheckErrors::NoSuchToken("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::BadAssetName,
        CheckErrors::NoSuchAsset("stackoos".to_string()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::BufferType(15).into()),
        CheckErrors::BadAssetName,
        CheckErrors::NoSuchAsset("stackoos".to_string()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::BufferType(15).into()),
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::NoSuchToken("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::IntType.into(),
                               AtomTypeIdentifier::BoolType.into()),
        CheckErrors::BadAssetName,
        CheckErrors::NoSuchAsset("stackoos".to_string()),
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::NoSuchToken("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::IntType.into(),
                               AtomTypeIdentifier::BoolType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
    ];

    let mut analysis_conn = AnalysisDatabaseConnection::memory();
    let mut db = analysis_conn.begin_save_point();
    for (script, expected_err) in bad_scripts.iter().zip(expected.iter()) {
        let tokens_contract = format!("{}\n{}", FIRST_CLASS_TOKENS, script);
        let mut tokens_contract = parse(&tokens_contract).unwrap();
        let actual_err = type_check(&"tokens", &mut tokens_contract, &mut db, true).unwrap_err();

        assert_eq!(&actual_err.err, expected_err);
    }
}
