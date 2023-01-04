(use-trait math .math-trait.math)

(define-data-var trait-var principal tx-sender)

(define-public (upcast (math-contract <math>))
  (begin
    (var-set trait-var math-contract)
    (ok (var-get trait-var))
  )
)
