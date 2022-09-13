(use-trait double .double-trait.double-method)

(define-public (call-double (double <double>))
  (contract-call? double foo u5)
)
