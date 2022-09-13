(use-trait math .math-trait.math)

(define-public (use (math-contract <math>))
  (ok true)
)

(define-public (pass-parital-impl-literal-as-trait)
  (use .partial-math-trait)
)
