(use-trait math .math-trait.math)

(define-public (downcast)
  (let ((p .math-trait-impl))
    (contract-call? p add u1 u2)
  )
)
