(use-trait double .double-trait.double-method)

(define-public (call-double (d <double>))
  (contract-call? d foo true)
)
