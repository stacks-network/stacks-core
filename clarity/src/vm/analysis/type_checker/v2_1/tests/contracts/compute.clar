(use-trait math-trait .math-trait.math)

(define-trait compute-trait (
  (compute (<math-trait> uint) (response uint uint))
))
