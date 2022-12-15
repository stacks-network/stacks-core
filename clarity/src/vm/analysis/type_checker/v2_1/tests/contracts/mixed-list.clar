(use-trait math .math-trait.math)

(define-public (take-traits (t (list 4 <math>)))
    (ok true)
)

(define-public (do-it (m <math>))
    (take-traits (list m .impl-math-trait))
)