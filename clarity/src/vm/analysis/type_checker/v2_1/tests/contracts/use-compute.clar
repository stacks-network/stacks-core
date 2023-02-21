(use-trait compute-trait .compute.compute-trait)
(use-trait math-trait .math-trait.math)

(define-public (do-it (computer <compute-trait>) (math-contract <math-trait>) (x uint))
  (contract-call? computer compute math-contract x)
)