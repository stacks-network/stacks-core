(define-read-only (foo)
  (bar)
)

(define-read-only (bar)
  (foo)
)
