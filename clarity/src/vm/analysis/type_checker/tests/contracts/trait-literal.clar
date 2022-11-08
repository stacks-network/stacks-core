(use-trait math .math-trait.math)

(define-public (use (math-contract <math>))
  (ok true)
)

(define-public (pass-literal-as-trait)
  (use .impl-math-trait)
)
