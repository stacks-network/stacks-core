(use-trait math .math-trait.math)

(define-private (get-math-impl) .impl-math-trait)

(define-constant principal-value (get-math-impl))

(define-public (downcast)
  (contract-call? principal-value add u1 u2)
)
