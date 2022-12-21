(use-trait math .math-trait.math)

(define-public (use (math-contract <math>))
  (ok true)
)

(define-public (downcast (arg principal))
  (use arg)
)
