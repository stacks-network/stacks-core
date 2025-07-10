(define-constant ERR_NOT_ALLOWED u101)

(define-constant INITIAL_MINT_AMOUNT u200000000000000) ;; 200,000,000 STX
(define-constant INITIAL_MINT_VESTING_ITERATIONS u24) ;; 24 months
(define-constant INITIAL_MINT_VESTING_ITERATION_BLOCKS u4383) ;; ~1 month of BTC blocks
(define-constant INITIAL_MINT_IMMEDIATE_AMOUNT u100000000000000) ;; 100,000,000 STX
(define-constant INITIAL_MINT_VESTING_AMOUNT (- INITIAL_MINT_AMOUNT INITIAL_MINT_IMMEDIATE_AMOUNT))

(define-data-var recipient principal tx-sender)

(define-data-var deploy-block-height uint burn-block-height)

(define-data-var last-vesting-claim-block (optional uint) none)

(define-data-var vested-claimed-amount uint u0)

(define-read-only (get-recipient) (var-get recipient))

(define-read-only (get-deploy-block-height) (var-get deploy-block-height))

(define-read-only (get-last-vesting-claim-block) (var-get last-vesting-claim-block))

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

;; Transfer the total balance of this contract to `recipient`.
;;
;; May only be called by the `recipient`.
;;
;; Returns the amount of STX transferred.
(define-public (claim)
    (let
        (
            (balance (stx-get-balance (as-contract tx-sender)))
        )
        (try! (validate-caller))
        (try! (as-contract (stx-transfer? balance tx-sender (var-get recipient))))
        (ok balance)
    )
)

(define-private (validate-caller)
    (ok (asserts! (is-eq contract-caller (var-get recipient)) (err ERR_NOT_ALLOWED)))
)

(define-read-only (calc-vested-amount (burn-height uint))
    (let
      (
        (diff (- burn-height (var-get deploy-block-height)))
        (iterations (/ diff INITIAL_MINT_VESTING_ITERATION_BLOCKS))
        (stx-per-iteration (/ INITIAL_MINT_VESTING_AMOUNT INITIAL_MINT_VESTING_ITERATIONS))
        (vesting-multiple (* stx-per-iteration iterations))
        (vesting-amount (if (> vesting-multiple INITIAL_MINT_VESTING_AMOUNT) INITIAL_MINT_VESTING_AMOUNT vesting-multiple))
        (total-amount (+ INITIAL_MINT_IMMEDIATE_AMOUNT vesting-amount))
      )
      (ok (- total-amount (var-get vested-claimed-amount)))
    )
)
