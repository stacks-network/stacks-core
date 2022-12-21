(use-trait double .double-trait.double-method)

(define-public (call-double-1 (double <double>))
  (contract-call? double foo u5)
)

(define-public (call-double-2 (double <double>))
  (contract-call? double foo true)
)
