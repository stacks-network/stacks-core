
;; title: sbtc-token-key-admin
;; version:
;; summary:
;; description:

;; traits
;;
(impl-trait 'SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE.sip-010-trait-ft-standard.sip-010-trait)

;; token definitions
;; 
(define-fungible-token sbtc u2100000000000000)

;; constants
;;
(define-constant contract-owner tx-sender)
(define-constant err-invalid-caller (err u1))
(define-constant err-owner-only (err u100))
(define-constant err-not-token-owner (err u101))

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

(define-public (delete-signer-key (id uint))
    (if (is-valid-caller)
        (ok (map-delete signers id))
        err-invalid-caller
    )
)

(define-public (mint! (amount uint))
    (if (is-valid-caller)
        (token-credit! tx-sender amount)
        err-invalid-caller
    )
)

(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
	(begin
		(asserts! (is-eq tx-sender sender) err-not-token-owner)
		(try! (ft-transfer? sbtc amount sender recipient))
		(match memo to-print (print to-print) 0x)
		(ok true)
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

;;(define-read-only (get-signers)
;;    (map-get? signers)
;;)

(define-read-only (get-name)
	(ok "sBTC")
)

(define-read-only (get-symbol)
	(ok "sBTC")
)

(define-read-only (get-decimals)
	(ok u0)
)

(define-read-only (get-balance (who principal))
	(ok (ft-get-balance sbtc who))
)

(define-read-only (get-total-supply)
	(ok (ft-get-supply sbtc))
)

(define-read-only (get-token-uri)
	(ok none)
)

;; private functions
;;
(define-private (is-valid-caller)
    (is-eq contract-owner tx-sender)
)

(define-private (token-credit! (account principal) (amount uint))
    (ft-mint? sbtc amount account)
)
