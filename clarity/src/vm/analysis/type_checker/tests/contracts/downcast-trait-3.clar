(use-trait math .math-trait.math)

(define-map principal-value {id: uint} {val: principal})

(define-public (use (math-contract <math>))
  (ok true)
)

(define-public (downcast)
  (use (unwrap-panic (get val (map-get? principal-value {id: u0}))))
)
