(define-read-only (static-sub-call (x uint) (y uint))
  (contract-call? .impl-math-trait sub x y)
)
