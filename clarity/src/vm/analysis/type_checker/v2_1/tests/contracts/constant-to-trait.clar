(use-trait math .math-trait.math)

(define-constant principal-value .impl-math-trait)

(define-public (use (math-contract <math>))
  (ok true)
)

(define-public (downcast)
  (use principal-value)
)
