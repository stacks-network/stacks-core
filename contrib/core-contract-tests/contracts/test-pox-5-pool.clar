(impl-trait .pox-5-pool-owner-trait.pool-owner-trait)

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
    ;; #[allow(unused_binding)]
    (unlock-bytes (buff 683))
  )
  (ok true)
)

;; #[allow(unnecessary_public)]
(define-public (validate-registration!
    (caller principal)
    ;; #[allow(unused_binding)]
    (signer-key (buff 33))
    ;; #[allow(unused_binding)]
    (pox-addr {
      version: (buff 1),
      hashbytes: (buff 32),
    })
  )
  (begin
    (asserts! (is-eq (var-get allowed-caller) caller) (err u1000))
    (ok true)
  )
)

(define-public (update-allowed-caller (new-allowed-caller principal))
  (ok (var-set allowed-caller new-allowed-caller))
)
