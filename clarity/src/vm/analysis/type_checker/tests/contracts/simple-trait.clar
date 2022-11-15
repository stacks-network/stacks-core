(define-trait simple (
  (simple () (response bool bool))
))

(define-public (call-simple (handle <simple>))
  (contract-call? handle simple)
)
