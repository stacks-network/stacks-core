(define-constant ERR_FAILED_ASSERTION u999)
(define-constant ERR_UNWRAP u998)
(define-constant ERR_UNEXPECTED_RESULT u997)
(define-constant ERR_IGNORED u996)

(define-constant DEPLOYER tx-sender)

(define-data-var last-iteration-claimed uint u0)
(define-data-var minted-initial bool false)

;; General helpers

;; Helper to simulate the initial balance of the SIP-031 contract. This should
;; be called by wallet_10, which has 200M STX. It transfers the initial 200M
;; STX to the contract.
(define-private (initial-mint-helper)
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

;; Helper to transfer extra STX amounts to the contract. In combination with
;; other tests, this ensures that extra transfers do not break the vesting
;; schedule.
(define-private (extra-transfer-to-contract-helper (ustx-amount uint))
  (ok
    (and
      (not (is-eq tx-sender 'ST3FFKYTTB975A3JC3F99MM7TXZJ406R3GKE6JV56))
      (> ustx-amount u0)
      (>= (stx-get-balance tx-sender) ustx-amount)
      (unwrap-panic (stx-transfer? ustx-amount tx-sender (as-contract tx-sender)))
    )
  )
)

;; Property tests

;; Helper to set up the Rendezvous testing environment for the property testing
;; routine. This will eventually be picked up during property testing runs.
(define-public (test-initial-mint-helper)
  (initial-mint-helper)
)

;; Helper to transfer extra STX amounts to the contract. This will eventually
;; be picked up during property testing runs.
(define-public (test-extra-transfer-helper (ustx-amount uint))
  (extra-transfer-to-contract-helper ustx-amount)
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
        (current-iteration (/ (- burn-block-height DEPLOY_BLOCK_HEIGHT) INITIAL_MINT_VESTING_ITERATION_BLOCKS))
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
        (var-set last-iteration-claimed current-iteration)
      )
    )
  )
)

;; Tests that the claimable amount is greater than the STX per iteration if the
;; last iteration claimed is less than the current iteration.
(define-public (test-claimable-amount-gt-iteration-stx)
  (ok
    (let (
        (recipient-balance-before (stx-get-balance (var-get recipient)))
        (claimable (calc-claimable-amount burn-block-height))
        (current-iteration (/ (- burn-block-height DEPLOY_BLOCK_HEIGHT) INITIAL_MINT_VESTING_ITERATION_BLOCKS))
      )
      (and
        (is-eq (var-get recipient) contract-caller tx-sender)
        (> claimable u0)
        (> current-iteration (var-get last-iteration-claimed))
        (asserts! (>= claimable STX_PER_ITERATION) (err claimable))
      )
    )
  )
)

;; Invariants

;; Public wrapper for initial mint setup, required for Rendezvous invariant 
;; testing. This will eventually be picked up during invariant testing runs.
(define-public (initial-mint-helper-invariant-runs)
  (if
    (is-eq (initial-mint-helper) (ok true))
    (ok true)
    (err ERR_IGNORED)
  )
)

;; Public wrapper for extra STX transfers to the contract for Rendezvous 
;; invariant testing. This will eventually be picked up during invariant
;; testing runs.
(define-public (extra-transfer-helper-invariant-runs (ustx-amount uint))
  (if
    (is-eq (extra-transfer-to-contract-helper ustx-amount) (ok true))
    (ok true)
    (err ERR_IGNORED)
  )
)

;; Tests that the recipient remains unchanged unless `update-recipient` was
;; called successfully at least once.
(define-read-only (invariant-recipient-unchanged)
  (if
    (is-eq
      u0
      (default-to u0 (get called (map-get? context "update-recipient")))
    )
    (is-eq (var-get recipient) DEPLOYER)
    true
  )
)

;; Tests that the amount returned by `calc-total-vested` never exceeds
;; the total initial mint amount, regardless of any extra transfers
;; to the contract.
(define-read-only (invariant-vested-lt-initial-mint (burn-height uint))
  (or
    (<= burn-height DEPLOY_BLOCK_HEIGHT)
    (<=
      (calc-total-vested burn-height)
      ;; We explicitly add up the total initial mint amount rather than using
      ;; `INITIAL_MINT_AMOUNT` directly. This ensures the invariant remains
      ;; valid even if the constants or their relationships change in the main
      ;; contract, making this invariant's feedback more robust.
      (+ INITIAL_MINT_IMMEDIATE_AMOUNT INITIAL_MINT_VESTING_AMOUNT)
    )
  )
)
