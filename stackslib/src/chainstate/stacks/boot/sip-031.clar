(define-constant ERR_NOT_ALLOWED u101)

(define-data-var recipient principal tx-sender)

(define-read-only (get-recipient) (var-get recipient))

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
