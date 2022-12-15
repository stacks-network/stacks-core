(use-trait math-alias .math-trait.math)

(define-public (add-call (math-contract <math-alias>) (x uint) (y uint))
  (contract-call? math-contract add x y)
)

(define-public (sub-call (math-contract <math-alias>) (x uint) (y uint))
  (contract-call? math-contract sub x y)
)
