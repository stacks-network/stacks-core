(define-trait foo (
  (foo (<bar>) (response bool bool))
))

(define-trait bar (
  (bar (<baz>) (response bool bool))
))

(define-trait baz (
))
