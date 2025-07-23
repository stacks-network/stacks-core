(define-constant ERR_FAILED_ASSERTION u999)
(define-constant ERR_UNWRAP u998)
(define-constant ERR_UNEXPECTED_RESULT u997)

(define-data-var minted-initial bool false)

;; Helper to set up the Rendezvous testing environment. This should be called
;; by wallet_10, which has 200M STX. It mints the initial 200M STX to the
;; contract.
(define-public (test-helper-initial-mint)
  (ok
    (and
      ;; Ensure that the caller is wallet_10 as per Devnet.toml. It was added
      ;; to the devnet with 200M STX for this operation.
      (is-eq tx-sender 'ST3FFKYTTB975A3JC3F99MM7TXZJ406R3GKE6JV56)
      (not (var-get minted-initial))
      (unwrap-panic (stx-transfer? INITIAL_MINT_AMOUNT tx-sender (as-contract tx-sender)))
      (var-set minted-initial true)
    )
  )
)

;; Tests that the recipient is updated if the caller is allowed.
(define-public (test-update-recipient-allowed (new-recipient principal))
  (ok
    (and
      (is-eq (var-get recipient) contract-caller tx-sender)
      (try! (update-recipient new-recipient))
      (asserts!
        (is-eq new-recipient (var-get recipient))
        (err ERR_FAILED_ASSERTION)
      )
    )
  )
)

;; Tests that the proper error is returned if the caller is not allowed.
(define-public (test-update-recipient-not-allowed (new-recipient principal))
  (ok
    (and
      (not (is-eq (var-get recipient) contract-caller tx-sender))
      (asserts!
        (is-eq
          (unwrap-err! (update-recipient new-recipient) (err ERR_UNWRAP))
          ERR_NOT_ALLOWED
        )
        (err ERR_FAILED_ASSERTION)
      )
    )
  )
)

;; Tests that the recipient is not updated if the caller is not allowed.
(define-public (test-update-recipient-not-allowed-no-effect
    (new-recipient principal)
  )
  (ok
    (let (
        (recipient-before (var-get recipient))
        (update-recipient-result (update-recipient new-recipient))
      )
      (and
        (not (is-eq recipient-before contract-caller tx-sender))
        (not (is-eq recipient-before new-recipient))
        (asserts!
          (is-eq (var-get recipient) recipient-before)
          (err ERR_FAILED_ASSERTION)
        )
      )
    )
  )
)

;; Tests that the proper error is returned if the caller is not allowed.
(define-public (test-claim-not-allowed)
  (ok
    (and
      (not (is-eq (var-get recipient) contract-caller tx-sender))
      (asserts!
        (is-eq
          (unwrap-err! (claim) (err ERR_UNWRAP))
          ERR_NOT_ALLOWED
        )
        (err ERR_FAILED_ASSERTION)
      )
    )
  )
)

;; Tests that the proper error is returned if there is nothing to claim.
(define-public (test-claim-nothing-to-claim)
  (ok
    (and
      (is-eq (var-get recipient) contract-caller tx-sender)
      (is-eq (calc-claimable-amount burn-block-height) u0)
      (asserts!
        (is-eq
          (unwrap-err! (claim) (err ERR_UNWRAP))
          ERR_NOTHING_TO_CLAIM
        )
        (err ERR_FAILED_ASSERTION)
      )
    )
  )
)

;; Tests that the claim is successful if the caller is allowed, and the
;; recipient balance increases by the claimable amount.
(define-public (test-claim-allowed)
  (ok
    (let (
        (recipient-balance-before (stx-get-balance (var-get recipient)))
        (claimable (calc-claimable-amount burn-block-height))
      )
      (and
        (is-eq (var-get recipient) contract-caller tx-sender)
        (> claimable u0)
        (asserts! (is-ok (claim)) (err ERR_UNEXPECTED_RESULT))
        (asserts!
          (is-eq
            (stx-get-balance (var-get recipient))
            (+ recipient-balance-before claimable)
          )
          (err ERR_FAILED_ASSERTION)
        )
      )
    )
  )
)