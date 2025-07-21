(define-data-var recipient principal tx-sender)

(define-public (update-recipient (new-recipient principal)) (begin
    (asserts! (is-eq tx-sender (var-get recipient)) (err u101))
    (var-set recipient new-recipient)
    (ok true)
)) ;; Returns (response bool uint)

(define-read-only (get-recipient) (var-get recipient))

(define-public (claim) (ok true) ) ;; Returns (response uint uint)