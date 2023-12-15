(define-public (test-vote)
    (let ((result (contract-call? .pox-4 vote-for-aggregated-public-key 0x u0 u0 (list))))
        (asserts! (is-eq result (err u10003)) (err "expected 10003"))
        (ok true)))