(use-trait empty .empty-trait.empty)
(use-trait math  .math-trait.math)

(define-public (use-empty (empty-contract <empty>))
  (ok true)
)

(define-public (use-math (math-contract <math>))
  (use-empty math-contract)
)
