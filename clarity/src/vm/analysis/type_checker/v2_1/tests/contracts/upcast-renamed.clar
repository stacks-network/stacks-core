(use-trait math .math-trait.math)

(define-data-var trait-var principal tx-sender)

(define-public (store-and-read-trait (math-contract <math>))
  (let ((renamed-math-contract math-contract))
    (var-set trait-var renamed-math-contract)
    (var-get trait-var)
  )
)
