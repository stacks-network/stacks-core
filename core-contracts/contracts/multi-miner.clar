;; The .hyperchains contract
(define-constant CONTRACT_ADDRESS (as-contract tx-sender))

(define-constant ERR_SIGNER_APPEARS_TWICE 101)
(define-constant ERR_NOT_ENOUGH_SIGNERS 102)
(define-constant ERR_INVALID_SIGNATURE 103)
(define-constant ERR_UNAUTHORIZED_CONTRACT_CALLER 104)
(define-constant ERR_MINER_ALREADY_SET 105)

;; SIP-018 Constants
(define-constant sip18-prefix 0x534950303138)
;; (define-constant (sha256 (unwrap-panic (to-consensus-buff { name: "hyperchain-multi-miner", version: "1.0.0", chain-id: u1 }))))
(define-constant sip18-domain-hash 0x81c24181e24119f609a28023c4943d3a41592656eb90560c15ee02b8e1ce19b8)
(define-constant sip18-data-prefix (concat sip18-prefix sip18-domain-hash))

;; Required number of signers
(define-constant signers-required u2)

;; List of miners
(define-data-var miners (optional (list 10 principal)) none)

(define-private (get-miners)
    (unwrap-panic (var-get miners)))

;; Set the hc miners for this contract. Can be called by *anyone*
;;  before the miner is set. This is an unsafe way to initialize the
;;  contract, because a re-org could allow someone to reinitialize
;;  this field. Instead, authors should initialize the variable
;;  directly at the data-var instantiation. This is used for testing
;;  purposes only. 
(define-public (set-miners (miners-to-set (list 10 principal)))
    (match (var-get miners) existing-miner (err ERR_MINER_ALREADY_SET) 
        (begin 
            (var-set miners (some miners-to-set))
            (ok true))))

(define-private (index-of-miner (to-check principal))
    (index-of (get-miners) to-check))

(define-private (test-is-none (to-check (optional uint)))
    (is-some to-check))

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

;; Remove this function in 2.1
;; (define-private (to-consensus-buff (block-data { block: (buff 32), withdrawal-root: (buff 32), target-tip: (buff 32), multi-contract: principal })) (ok 0x00))

(define-private (make-block-commit-hash (block-data { block: (buff 32), withdrawal-root: (buff 32), target-tip: (buff 32) }))
    (let ((data-buff (unwrap-panic (to-consensus-buff (merge block-data { multi-contract: CONTRACT_ADDRESS }))))
          (data-hash (sha256 data-buff))
          ;; in 2.0, this is a constant: 0xe2f4d0b1eca5f1b4eb853cd7f1c843540cfb21de8bfdaa59c504a6775cd2cfe9
          (structured-hash (sha256 (concat sip18-data-prefix data-hash))))
          structured-hash))

(define-private (verify-sign-helper (curr-signature (buff 65))
                                    (accum (response { block-hash: (buff 32), signers: (list 9 principal) } int)))
    (match accum
        prior-okay (let ((curr-signer-pk (unwrap! (secp256k1-recover? (get block-hash prior-okay) curr-signature)
                                                (err ERR_INVALID_SIGNATURE)))
                         (curr-signer (unwrap! (principal-of? curr-signer-pk) (err ERR_INVALID_SIGNATURE))))
                        (ok { block-hash: (get block-hash prior-okay),
                              signers: (unwrap-panic (as-max-len? (append (get signers prior-okay) curr-signer) u9)) }))
        prior-err (err prior-err)))

(define-public (commit-block  (block-data { block: (buff 32), withdrawal-root: (buff 32), target-tip: (buff 32) })
                              (signatures (list 9 (buff 65))))
    (let ((block-data-hash (make-block-commit-hash block-data))
          (signer-principals (try! (fold verify-sign-helper signatures (ok { block-hash: block-data-hash, signers: (list) })))))
         ;; check that the caller is a direct caller!
         (asserts! (is-eq tx-sender contract-caller) (err ERR_UNAUTHORIZED_CONTRACT_CALLER))
         ;; check that we have enough signatures
         (try! (check-miners (append (get signers signer-principals) tx-sender)))
         ;; execute the block commit
         (as-contract (contract-call? .hyperchains commit-block (get block block-data) (get target-tip block-data) (get withdrawal-root block-data)))))
