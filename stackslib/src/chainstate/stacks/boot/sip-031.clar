;; This contract implements a boot contract, deployed
;; at epoch 3.2, which facilitates the mints and transfers
;; described in SIP-031.
;;
;; There are three mechanisms for claiming STX from this contract:
;; 1. An initial 100M STX, which is available immediately.
;; 2. A linear vesting schedule of 100M STX over 24 months.
;; 3. Per-tenure mints, which are transferred to this contract,
;;   are available as soon as they are received by this contract.
;;
;; This contract is written based on the assumption that the contract
;; will have a balance of at least 200M STX upon deployment, which is
;; handled during the epoch 3.2 transition.

(define-constant ERR_NOT_ALLOWED u101)
(define-constant ERR_NOTHING_TO_CLAIM u102)
(define-constant ERR_INVALID_RECIPIENT u103)

;; The amount initially minted to the contract is 200M STX
(define-constant INITIAL_MINT_AMOUNT u200000000000000) ;; 200,000,000 STX

;; Of the initial mint, 100M vests over 24 months
(define-constant INITIAL_MINT_VESTING_ITERATIONS u24) ;; 24 months

;; The number of burn blocks in a month
(define-constant INITIAL_MINT_VESTING_ITERATION_BLOCKS u4383) ;; ~1 month of BTC blocks

;; The amount of STX that is immediately available to claim from the initial mint
(define-constant INITIAL_MINT_IMMEDIATE_AMOUNT u100000000000000) ;; 100,000,000 STX

;; The amount of STX that is vested over the 24 months
(define-constant INITIAL_MINT_VESTING_AMOUNT (- INITIAL_MINT_AMOUNT INITIAL_MINT_IMMEDIATE_AMOUNT))

;; The amount of STX that is vested per iteration
(define-constant STX_PER_ITERATION (/ INITIAL_MINT_VESTING_AMOUNT INITIAL_MINT_VESTING_ITERATIONS))

;; The block height at which vesting starts. On Mainnet, this is
;; burn height 907740, which is what is specified in SIP-031.
(define-constant DEPLOY_BLOCK_HEIGHT (if is-in-mainnet
  u907740
  burn-block-height
))

;; The authorized recipient of the funds.
;; Note that in production environments, `tx-sender` is
;; replaced with a hard-coded address.
(define-data-var recipient principal tx-sender)

(define-read-only (get-recipient)
  (var-get recipient)
)

(define-read-only (get-deploy-block-height)
  DEPLOY_BLOCK_HEIGHT
)

;; Update the recipient of the funds.
;; May only be called by the current `recipient`.
;; Returns `true` if the recipient was updated.
(define-public (update-recipient (new-recipient principal))
  (begin
    (try! (validate-caller))
    (asserts! (is-standard new-recipient) (err ERR_INVALID_RECIPIENT))
    (print {
      topic: "update-recipient",
      old-recipient: (var-get recipient),
      new-recipient: new-recipient,
    })
    (var-set recipient new-recipient)
    (ok true)
  )
)

;; Transfer all currently withdrawable STX (vested + extra) to `recipient`.
;; Errors with `ERR_NOTHING_TO_CLAIM` if there is nothing to withdraw.
(define-public (claim)
  (let ((claimable (calc-claimable-amount burn-block-height)))
    (try! (validate-caller))
    (asserts! (> claimable u0) (err ERR_NOTHING_TO_CLAIM))
    (try! (as-contract (stx-transfer? claimable tx-sender (var-get recipient))))
    (print {
      topic: "claim",
      claimable: claimable,
      recipient: (var-get recipient),
    })
    (ok claimable)
  )
)

;; Authorization check. Verify that the caller is the current `recipient`.
;; This also prevents `recipient` calling into this contract
;; via an indirect contract-call.
(define-private (validate-caller)
  (if (is-eq (var-get recipient) contract-caller tx-sender)
    (ok true)
    (err ERR_NOT_ALLOWED)
  )
)

;; Returns the *total* vested amount at `burn-height`, i.e.
;; immediate bucket + linear vesting so far (DOES NOT subtract any claims).
(define-private (calc-total-vested (burn-height uint))
  (let (
      (diff (- burn-height DEPLOY_BLOCK_HEIGHT))
      ;; Note: this rounds down
      (iterations (/ diff INITIAL_MINT_VESTING_ITERATION_BLOCKS))
      (vested-multiple (* STX_PER_ITERATION iterations))
      ;; If we have completed (or exceeded) the scheduled number of iterations,
      ;; consider the *entire* vesting bucket unlocked. This avoids leaving a
      ;; tiny remainder caused by integer-division truncation.
      (vested-amount (if (>= iterations INITIAL_MINT_VESTING_ITERATIONS)
        INITIAL_MINT_VESTING_AMOUNT
        vested-multiple
      ))
      (total-amount (+ INITIAL_MINT_IMMEDIATE_AMOUNT vested-amount))
    )
    total-amount
  )
)

;; Returns the amount of STX that is claimable from the vested balance at `burn-height`.
;; Note that this function takes into account the current STX balance
;; of this contract, which may change by `burn-height`.
(define-read-only (calc-claimable-amount (burn-height uint))
  (if (< burn-height DEPLOY_BLOCK_HEIGHT)
    u0
    (let (
        (reserved (- INITIAL_MINT_AMOUNT (calc-total-vested burn-height)))
        (balance (stx-get-balance (as-contract tx-sender)))
        (claimable (if (> balance reserved)
          (- balance reserved)
          u0
        ))
      )
      claimable
    )
  )
)
