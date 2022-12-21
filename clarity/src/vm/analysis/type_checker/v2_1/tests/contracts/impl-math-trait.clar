(impl-trait .math-trait.math)
(define-read-only (add (x uint) (y uint)) (ok (+ x y)) )
(define-read-only (sub (x uint) (y uint)) (ok (- x y)) )
