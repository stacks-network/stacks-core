(impl-trait .math-trait.math)
(define-read-only (add (x uint) (y uint)) (ok (+ x y)) )
(define-read-only (sub (x uint) (y uint)) (ok (- x y)) )

(use-trait math .math-trait.math)

(define-public (use (math-contract <math>))
  (ok true)
)

(define-public (downcast)
  (as-contract (use tx-sender))
)
