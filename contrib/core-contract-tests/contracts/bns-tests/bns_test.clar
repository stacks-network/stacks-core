(define-constant ERR_NAMESPACE_NOT_FOUND 1005)

;; @name: test preorder and publish with invalid names
;; @caller: wallet_1
(define-public (test-name-registration)
    (begin
        (unwrap! (contract-call? .bns name-preorder 0x0123456789abcdef01230123456789abcdef0123 u1000000) (err "preorder should succeeed"))
        (let ((result (contract-call? .bns name-register  0x123456 0x123456 0x123456 0x)))
            (asserts! (is-eq result (err ERR_NAMESPACE_NOT_FOUND)) (err "registration should fail"))
            (ok true))))
