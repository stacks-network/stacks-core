(define-constant ERR_NOT_ALLOWED u101)
(define-constant ERR_NOTHING_TO_CLAIM u102)

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

(define-data-var recipient principal tx-sender)

(define-data-var deploy-block-height uint burn-block-height)

(define-data-var vested-claimed-amount uint u0)

(define-read-only (get-recipient) (var-get recipient))

(define-read-only (get-deploy-block-height) (var-get deploy-block-height))

(define-read-only (get-vested-claimed-amount) (var-get vested-claimed-amount))

;; Update the recipient of the funds.
;;
;; May only be called by the `recipient`.
;;
;; Returns `true` if the recipient was updated.
(define-public (update-recipient (new-recipient principal)) (begin
    (try! (validate-caller))
    (var-set recipient new-recipient)
    (ok true)
))

;; Transfer all currently withdrawable STX (vested + extra) to `recipient`.
;; Errors with `ERR_NOTHING_TO_CLAIM` if there is nothing to withdraw.
(define-public (claim)
    (let
        (
            (balance        (stx-get-balance (as-contract tx-sender)))
            (burn-height    burn-block-height)
            (total-vested   (calc-total-vested burn-height))
            (vested-claimed (var-get vested-claimed-amount))
            ;; Vested that has not yet been claimed
            (available-vested (- total-vested vested-claimed))
            ;; Portion of the initial mint that is *still* locked (not yet vested)
            (reserved (- INITIAL_MINT_AMOUNT total-vested))
            ;; Free balance = everything the caller may withdraw right now
            (claimable
                (if (> balance reserved)
                    (- balance reserved)
                    u0))
            (vested-to-claim (if (> available-vested claimable) claimable available-vested))
            (extra-to-claim  (- claimable vested-to-claim))
        )
        (try! (validate-caller))
        (asserts! (> claimable u0) (err ERR_NOTHING_TO_CLAIM))
        (var-set vested-claimed-amount (+ vested-claimed vested-to-claim))

        (try! (as-contract (stx-transfer? claimable tx-sender (var-get recipient))))
        (ok claimable)
        )
)

(define-private (validate-caller)
    (ok (asserts! (is-eq contract-caller (var-get recipient)) (err ERR_NOT_ALLOWED)))
)

;; Returns the *total* vested amount at `burn-height`, i.e.
;; immediate bucket + linear vesting so far ( DOES NOT subtract any claims ).
(define-private (calc-total-vested (burn-height uint))
    (let
      (
        (diff (- burn-height (var-get deploy-block-height)))
        (iterations (/ diff INITIAL_MINT_VESTING_ITERATION_BLOCKS))
        (stx-per-iteration (/ INITIAL_MINT_VESTING_AMOUNT INITIAL_MINT_VESTING_ITERATIONS))
        (vesting-multiple (* stx-per-iteration iterations))

        ;; If we have completed (or exceeded) the scheduled number of iterations,
        ;; consider the *entire* vesting bucket unlocked.  This avoids leaving a
        ;; tiny remainder caused by integer-division truncation.
        (vesting-amount (if (>= iterations INITIAL_MINT_VESTING_ITERATIONS)
                            INITIAL_MINT_VESTING_AMOUNT
                            vesting-multiple))
        (total-amount (+ INITIAL_MINT_IMMEDIATE_AMOUNT vesting-amount))
      )
      total-amount
    )
)

;; Returns the amount of STX that is vested at `burn-height`
(define-read-only (calc-vested-amount (burn-height uint))
    (let
      (
        (total-vested (calc-total-vested burn-height))
      )
      (ok (- total-vested (var-get vested-claimed-amount)))
    )
)
