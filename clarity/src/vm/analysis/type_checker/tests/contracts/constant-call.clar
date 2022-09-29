(define-constant principal-value .impl-math-trait)

(define-public (constant-call)
  (contract-call? principal-value add u1 u2)
)
