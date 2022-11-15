(use-trait math .math-trait.math)

(define-public (add-call (math-contract <math>) (x uint) (y uint))
  (contract-call? math-contract add x y)
)

(define-public (add-call-indirect (math-contract <math>) (x uint) (y uint))
  (let ((new-math-contract math-contract))
    (add-call new-math-contract x y)
  )
)
