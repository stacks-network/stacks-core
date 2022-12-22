(define-public (foo)
  (ok true)
)

(define-read-only (bar)
  (foo)
)
