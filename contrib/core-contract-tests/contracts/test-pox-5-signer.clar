(impl-trait .pox-5.signer-manager-trait)
(use-trait signer-manager-trait .pox-5.signer-manager-trait)

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
    (signer-calldata (optional (buff 500)))
  )
  (ok true)
)

(define-public (update-allowed-caller (new-allowed-caller principal))
  (ok (var-set allowed-caller new-allowed-caller))
)

(define-public (register-self
    (signer-manager <signer-manager-trait>)
    (signer-key (buff 33))
    (auth-id uint)
    (signer-sig (buff 65))
  )
  (as-contract? ()
    (try! (contract-call? .pox-5 grant-signer-key signer-key current-contract auth-id
      signer-sig
    ))
    (try! (contract-call? .pox-5 register-signer signer-manager signer-key))
  )
)
