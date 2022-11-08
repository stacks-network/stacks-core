(use-trait math .math-trait.math)

(define-data-var principal-value principal .impl-math-trait)

(define-public (use (math-contract <math>))
  (ok true)
)

(define-public (downcast)
  (use (var-get principal-value))
)
