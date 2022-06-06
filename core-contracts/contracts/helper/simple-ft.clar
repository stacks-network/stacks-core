(define-constant ERR_NOT_AUTHORIZED (err u1001))

(impl-trait .trait-standards.ft-trait)
(impl-trait .trait-standards.mint-from-hyperchain-trait)

(define-fungible-token ft-token)

;; get the token balance of owner
(define-read-only (get-balance (owner principal))
  (begin
    (ok (ft-get-balance ft-token owner))))

;; returns the total number of tokens
(define-read-only (get-total-supply)
  (ok (ft-get-supply ft-token)))

;; returns the token name
(define-read-only (get-name)
  (ok "ft-token"))

;; the symbol or "ticker" for this token
(define-read-only (get-symbol)
  (ok "EXFT"))

;; the number of decimals used
(define-read-only (get-decimals)
  (ok u0))

;; Implement mint-from-hyperchain trait
(define-public (mint-from-hyperchain (amount uint) (sender principal) (recipient principal))
    (begin
        ;; Check that the tx-sender is the provided sender
        (asserts! (is-eq tx-sender sender) ERR_NOT_AUTHORIZED)

        (ft-mint? ft-token amount recipient)
    )
)


;; Transfers tokens to a recipient
(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
    (begin
      (try! (ft-transfer? ft-token amount sender recipient))
      (print memo)
      (ok true)
    )
)

(define-read-only (get-token-uri)
  (ok none))

(define-public (gift-tokens (recipient principal))
  (begin
    (asserts! (is-eq tx-sender recipient) ERR_NOT_AUTHORIZED)
    (ft-mint? ft-token u1 recipient)
  )
)