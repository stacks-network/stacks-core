(use-trait empty .empty-trait.empty)
(use-trait math  .math-trait.math)

(define-public (use-empty (empty-contract <empty>))
  (use-math empty-contract)
)

(define-public (use-math (math-contract <math>))
  (ok true)
)
