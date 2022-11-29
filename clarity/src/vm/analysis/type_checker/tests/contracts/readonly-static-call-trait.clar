(use-trait math .math-trait.math)

(define-public (sub-call (math-contract <math>) (x uint) (y uint))
  (contract-call? math-contract sub x y)
)

(define-read-only (static-sub-call (x uint) (y uint))
  (sub-call .impl-math-trait x y)
)
