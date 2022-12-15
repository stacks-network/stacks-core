(use-trait math .math-trait.math)

(define-private (return-principal) .impl-math-trait)

(define-constant principal-value (return-principal))

(define-public (use (math-contract <math>))
  (ok true)
)

(define-public (downcast)
  (use principal-value)
)
