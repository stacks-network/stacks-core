;; The .hyperchains contract
(define-constant CONTRACT_ADDRESS (as-contract tx-sender))

(define-constant ERR_SIGNER_APPEARS_TWICE 101)
(define-constant ERR_NOT_ENOUGH_SIGNERS 102)
(define-constant ERR_INVALID_SIGNATURE 103)
(define-constant ERR_UNAUTHORIZED_CONTRACT_CALLER 104)


;; Required number of signers
(define-constant signers-required u2)

;; List of miners
(define-constant miners
    (list  'ST1AW6EKPGT61SQ9FNVDS17RKNWT8ZP582VF9HSCP
           'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5
           'ST2GE6HSXT81X9X3ATQ14WPT49X915R8X7FVERMBP
           'ST18F1AHKW194BWQ3CEFDPWVRARA79RBGFEWSDQR8))

(define-private (index-of-miner (to-check principal))
    (index-of miners to-check))

(define-private (test-is-none (to-check (optional uint)))
    (is-none to-check))

(define-private (unique-helper (item (optional uint)) (accum { all-unique: bool,  priors: (list 10 uint)}))
    (if (not (get all-unique accum))
        { all-unique: false, priors: (list) }
        (if (is-some (index-of (get priors accum) (unwrap-panic item)))
            { all-unique: false, priors: (list) }
            { all-unique: true,
              priors: (unwrap-panic (as-max-len? (append (get priors accum) (unwrap-panic item)) u10)) })))

(define-private (check-miners (provided-set (list 10 principal)))
    (let ((provided-checked (filter test-is-none (map index-of-miner provided-set)))
          (uniques-checked (fold unique-helper provided-checked { all-unique: true, priors: (list)})))
         (asserts! (get all-unique uniques-checked) (err ERR_SIGNER_APPEARS_TWICE))
         (asserts! (>= (len provided-checked) signers-required) (err ERR_NOT_ENOUGH_SIGNERS))
         (ok true)))

(define-private (make-block-commit-hash (block-data { block: (buff 32), withdrawal-root: (buff 32) }))
    ;; todo: use 2.1 to-consensus-hash
    0x0000000000000000000000000000000000000000000000000000000000000000)

(define-private (verify-sign-helper (curr-signature (buff 65))
                                    (accum (response { block-hash: (buff 32), signers: (list 9 principal) } int)))
    (match accum
        prior-okay (let ((curr-signer-pk (unwrap! (secp256k1-recover? (get block-hash prior-okay) curr-signature)
                                                (err ERR_INVALID_SIGNATURE)))
                         (curr-signer (unwrap! (principal-of? curr-signer-pk) (err ERR_INVALID_SIGNATURE))))
                        (ok { block-hash: (get block-hash prior-okay),
                              signers: (unwrap-panic (as-max-len? (append (get signers prior-okay) curr-signer) u9)) }))
        prior-err (err prior-err)))

(define-public (commmit-block (block-data { block: (buff 32), withdrawal-root: (buff 32) })
                              (signatures (list 9 (buff 65))))
    (let ((block-data-hash (make-block-commit-hash block-data))
          (signer-principals (try! (fold verify-sign-helper signatures (ok { block-hash: block-data-hash, signers: (list) })))))
         ;; check that the caller is a direct caller!
         (asserts! (is-eq tx-sender contract-caller) (err ERR_UNAUTHORIZED_CONTRACT_CALLER))
         ;; check that we have enough signatures
         (try! (check-miners (append (get signers signer-principals) tx-sender)))
         ;; execute the block commit
         (as-contract (contract-call? .hyperchains commit-block (get block block-data) (get withdrawal-root block-data)))))
