(define-constant ERR_NOT_ALLOWED 101)

(define-data-var recipient principal tx-sender)

(define-public (update-recipient (new-recipient principal)) (begin
    (asserts! (is-eq contract-caller (var-get recipient)) (err ERR_NOT_ALLOWED))
    (var-set recipient new-recipient)
    (ok true)
))

(define-read-only (get-recipient) (var-get recipient))

(define-public (claim) (ok true))