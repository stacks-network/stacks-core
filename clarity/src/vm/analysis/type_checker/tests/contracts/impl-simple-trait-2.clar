(impl-trait .simple-trait.simple)
(define-public (simple)
  (contract-call? .simple-trait call-simple .impl-simple-trait)
)
