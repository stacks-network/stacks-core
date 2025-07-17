(define-data-var recipient principal 'ST000000000000000000002AMW42H)

(define-public (update-recipient (new-recipient principal)) (begin
    (asserts! (is-eq tx-sender (var-get recipient)) (err u101))
    (var-set recipient new-recipient)
    (ok true)
)) ;; Returns (response bool uint)

(define-read-only (get-recipient) (ok (var-get recipient))) ;; Returns (response principal uint)

(define-public (claim) (ok true) ) ;; Returns (response uint uint)