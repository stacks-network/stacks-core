(impl-trait .pox-5.pool-owner-trait)
(use-trait pool-owner-trait .pox-5.pool-owner-trait)

;; default to allowing deployer to register as a pool
(define-data-var allowed-caller principal tx-sender)

;; #[allow(unnecessary_public)]
(define-public (validate-stake!
    ;; #[allow(unused_binding)]
    (staker principal)
    ;; #[allow(unused_binding)]
    (amount-ustx uint)
    ;; #[allow(unused_binding)]
    (num-cycles uint)
  )
  (ok true)
)

(define-public (update-allowed-caller (new-allowed-caller principal))
  (ok (var-set allowed-caller new-allowed-caller))
)

(define-public (register-self
    (signer-key (buff 33))
    (pool-owner <pool-owner-trait>)
  )
  (as-contract? ((with-all-assets-unsafe))
    (try! (contract-call? .pox-5 register-pool pool-owner signer-key))
  )
)
