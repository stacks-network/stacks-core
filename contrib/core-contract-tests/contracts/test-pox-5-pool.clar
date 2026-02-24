(impl-trait .pox-5-pool-owner-trait.pool-owner-trait)

;; default to allowing deployer to register as a pool
(define-data-var allowed-registering-tx-sender principal tx-sender)

;; #[allow(unnecessary_public)]
(define-public (validate-stake!
    ;; #[allow(unused_binding)]
    (staker principal) (amount-ustx uint) (num-cycles uint) (unlock-bytes (buff 255)))
  (ok true)
)

;; #[allow(unnecessary_public)]
(define-public (validate-registration! (registering-tx-sender principal) (signer-key (buff 33)) (pox-addr {
  version: (buff 1),
  hashbytes: (buff 32),
}))
  (begin
    (asserts! (is-eq (var-get allowed-registering-tx-sender) registering-tx-sender) (err u1000))
    (ok true)
  )
)

(define-public (update-allowed-registering-tx-sender (new-allowed-registering-tx-sender principal))
  (ok (var-set allowed-registering-tx-sender new-allowed-registering-tx-sender))
)