;; (define-data-var test <fungible-token-trait>)

(use-trait token-a-trait 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF.token-a.token-trait)

(define-map traded-bases
  ((base-ft principal))
  ((registered-at uint)))

(define-map traded-quotes
  ((base-ft principal) (quote-ft principal))
  ((volume uint) (registered-at uint)))

(define-public (forward-get-balance (user principal) (contract <token-a-trait>))
  (begin
    (contract-call? contract get-balance user)
    (ok 1)))

(define-public (forward-transfer? (sender principal) (recipient principal) (amount uint) (token-contract <token-a-trait>))
  (begin
    (contract-call? contract transfer? sender recipient amount)
    (ok 1)))

;;(define-public (get-balance (user principal) (contract <non-fungible-token-trait>))
;;    (ok 1))

;; (define-map mempool
;;   ((base ?) (quote ?))
;;   ((volume uint) (price uint) (maker principal) (created-at uint)))
;;
;; (define-map filled-orders
;;   ((base ?) (quote ?))
;;   ((maker principal) (taker principal) (volume uint) (price uint) (executed-at uint)))
;;
;; (define-map )
;;
;; (define-public (register-order (price uint) 
;;                                (volume uint) 
;;                                (base-ft fungible-token-trait) 
;;                                (quote-ft fungible-token-trait))
;;   (begin
;;     (contract-call? token-a transfer user-a user-b qty-token-a)
;;     ()))
;;
;; (define-public (make-order (base-qty uint) 
;;                            (quote-qty uint) 
;;                            (base-ft fungible-token-trait) 
;;                            (quote-ft fungible-token-trait))
;;     (begin
;;         (contract-call? token-a transfer user-a user-b qty-token-a)
;;         (contract-call? token-b transfer user-b user-a qty-token-b)))
;;
;; (define-public (take-order (base-qty uint) 
;;                            (quote-qty uint) 
;;                            (base-ft fungible-token-trait) 
;;                            (quote-ft fungible-token-trait))
;;     (begin
;;         (contract-call? token-a transfer user-a user-b qty-token-a)
;;         (contract-call? token-b transfer user-b user-a qty-token-b)))
;;
;; (define-public (claim-remainder ()))
;;
;;
;; (principal-of base-ft)