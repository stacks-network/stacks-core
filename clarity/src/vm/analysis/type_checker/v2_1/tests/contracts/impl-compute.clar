(impl-trait .compute.compute-trait)
(use-trait math-trait .math-trait.math)

(define-public (compute (m <math-trait>) (arg uint))
  (contract-call? m add arg u1)
)
