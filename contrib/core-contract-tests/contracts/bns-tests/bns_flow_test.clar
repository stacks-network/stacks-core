(define-constant ERR_NAMESPACE_NOT_FOUND 1005)

;; @name: test delegation to wallet_2, stacking and revoking
(define-public (test-name-registration)
    (begin
        ;; @caller wallet_1
        (unwrap! (contract-call? .bns name-preorder 0x0123456789abcdef01230123456789abcdef0123 u1000000) (err "name-preorder by wallet 1 should succeed"))
        ;; @caller wallet_2
        (unwrap! (contract-call? .bns name-preorder 0x30123456789abcdef01230123456789abcdef012 u1000000) (err "name-preorder by wallet 2 should succeed"))

        ;; @mine-blocks-before 100
        ;; @caller wallet_1
        (try! (register))
        (ok true)))

(define-public (register)
    (let ((result (contract-call? .bns name-register 0x123456 0x123456 0x123456 0x)))
            (asserts! (is-eq result (err ERR_NAMESPACE_NOT_FOUND)) (err "name-register should fail"))
            (ok true)))