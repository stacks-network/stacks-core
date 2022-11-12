(use-trait math .math-trait.math)

(define-private (identity (x principal)) x)

(define-public (upcast (math-contract <math>))
  (ok (identity math-contract))
)
