use vm::types::AtomTypeIdentifier;
use vm::parser::parse;
use vm::checker::errors::CheckErrors;
use vm::checker::{AnalysisDatabase};

const FIRST_CLASS_TOKENS: &str = "(define-fungible-token stackaroos)
         (define-non-fungible-token stacka-nfts (buff 10))
         (nft-get-owner stacka-nfts \"1234567890\" )
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
               (err 8)))
         (begin (ft-mint! stackaroos 10000 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
                (ft-mint! stackaroos 200 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
                (ft-mint! stackaroos 4   'CTtokens))";

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
           (let ((xfer-result (contract-call! tokens my-token-transfer
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

#[test]
fn test_names_tokens_contracts() {
    use vm::checker::type_check;

    let mut tokens_contract = parse(FIRST_CLASS_TOKENS).unwrap();
    let mut names_contract = parse(ASSET_NAMES).unwrap();
    let mut db = AnalysisDatabase::memory();

    type_check(&"tokens", &mut tokens_contract, &mut db, true).unwrap();
    type_check(&"names", &mut names_contract, &mut db, true).unwrap();
}


#[test]
fn test_bad_asset_usage() {
    use vm::checker::type_check;

    let bad_scripts = ["(ft-get-balance stackoos tx-sender)",
                       "(ft-get-balance 1234 tx-sender)",
                       "(ft-get-balance stackaroos 100)",
                       "(nft-get-owner 1234 \"abc\")",
                       "(nft-get-owner stackoos \"abc\")",
                       "(nft-get-owner stacka-nfts 1234 )",
                       "(nft-get-owner stacka-nfts \"123456789012345\" )",
                       "(nft-mint! 1234 \"abc\" tx-sender)",
                       "(nft-mint! stackoos \"abc\" tx-sender)",
                       "(nft-mint! stacka-nfts 1234 tx-sender)",
                       "(nft-mint! stacka-nfts \"123456789012345\" tx-sender)",
                       "(nft-mint! stacka-nfts \"abc\" 2)",
                       "(ft-mint! stackoos 1 tx-sender)",
                       "(ft-mint! 1234 1 tx-sender)",
                       "(ft-mint! stackaroos 2 100)",
                       "(ft-mint! stackaroos 'true tx-sender)",
                       "(nft-transfer! 1234 \"a\" tx-sender tx-sender)",
                       "(nft-transfer! stackoos    \"a\" tx-sender tx-sender)",
                       "(nft-transfer! stacka-nfts \"a\" 2 tx-sender)",
                       "(nft-transfer! stacka-nfts \"a\" tx-sender 2)",
                       "(nft-transfer! stacka-nfts 2 tx-sender tx-sender)",
                       "(ft-transfer! stackoos 1 tx-sender tx-sender)",
                       "(ft-transfer! 1234 1 tx-sender tx-sender)",
                       "(ft-transfer! stackaroos 2 100 tx-sender)",
                       "(ft-transfer! stackaroos 'true tx-sender tx-sender)",
                       "(ft-transfer! stackaroos 2 tx-sender 100)",
                       "(define-fungible-token stackaroos 'true)",
                       "(define-non-fungible-token stackaroos integer)",
    ];

    let expected = [
        CheckErrors::NoSuchFT("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::BadTokenName,
        CheckErrors::NoSuchNFT("stackoos".to_string()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::BufferType(15).into()),
        CheckErrors::BadTokenName,
        CheckErrors::NoSuchNFT("stackoos".to_string()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::BufferType(15).into()),
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::NoSuchFT("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::IntType.into(),
                               AtomTypeIdentifier::BoolType.into()),
        CheckErrors::BadTokenName,
        CheckErrors::NoSuchNFT("stackoos".to_string()),
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::BufferType(10).into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::NoSuchFT("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::IntType.into(),
                               AtomTypeIdentifier::BoolType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::PrincipalType.into(),
                               AtomTypeIdentifier::IntType.into()),
        CheckErrors::TypeError(AtomTypeIdentifier::IntType.into(),
                               AtomTypeIdentifier::BoolType.into()),
        CheckErrors::DefineNFTBadSignature.into(),
    ];

    let mut db = AnalysisDatabase::memory();
    for (script, expected_err) in bad_scripts.iter().zip(expected.iter()) {
        let tokens_contract = format!("{}\n{}", FIRST_CLASS_TOKENS, script);
        let mut tokens_contract = parse(&tokens_contract).unwrap();
        let actual_err = type_check(&"tokens", &mut tokens_contract, &mut db, true).unwrap_err();

        assert_eq!(&actual_err.err, expected_err);
    }
}
