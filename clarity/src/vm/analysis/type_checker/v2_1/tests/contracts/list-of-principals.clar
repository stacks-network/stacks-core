(use-trait math .math-trait.math)

(define-public (take-traits (t (list 4 <math>)))
    (ok true)
)

(define-public (do-it)
    (take-traits (list .impl-math-trait .impl-math-trait))
)