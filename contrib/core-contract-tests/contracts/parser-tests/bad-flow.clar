;;@name bad annotation flow test
(define-public (test-bad-flow)
    (begin
        ;; @caller wallet_1
        (try! (my-test-function))
        (unwrap! (contract-call? invalid-syntax))
        (unwrap! (contract-call? .bns))
        (ok true)))


(define-private (my-test-function)
    (ok true))