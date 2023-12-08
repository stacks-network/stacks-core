;;@name simple flow test
(define-public (test-simple-flow)
    (begin
        ;; @caller wallet_1
        (try! (my-test-function))
        ;; @caller wallet_2
        (unwrap! (contract-call? .bns name-resolve 0x 0x))
        (ok true)))

(define-public (my-test-function)
    (ok true))