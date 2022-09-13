(use-trait math .math-trait.math)

(define-read-only (readonly-sub-call (math-contract <math>) (x uint) (y uint))
  (contract-call? math-contract sub x y)
)
