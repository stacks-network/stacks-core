
;; title: key-admin
;; version:
;; summary:
;; description:

;; traits
;;

;; token definitions
;; 

;; constants
;;
(define-constant contract-owner tx-sender)
(define-constant err-invalid-caller (err u1))

;; data vars
;;
(define-data-var coordinator (optional principal) none)

;; data maps
;;
(define-map signers uint principal)

;; public functions
;;
(define-public (set-coordinator-key (key principal))
    (if (is-valid-caller)
        (ok (var-set coordinator (some key)))
        err-invalid-caller
    )
)

(define-public (set-signer-key (id uint) (key principal))
    (if (is-valid-caller)
        (ok (map-set signers id key))
        err-invalid-caller
    )
)

;; read only functions
;;
(define-read-only (get-coordinator-key)
  (var-get coordinator)
)

(define-read-only (get-signer-key (signer uint))
  (map-get? signers signer)
)

;; private functions
;;
(define-private (is-valid-caller)
    (is-eq contract-owner tx-sender)
)

