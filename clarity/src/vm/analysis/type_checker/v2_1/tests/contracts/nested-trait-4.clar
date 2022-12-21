(use-trait empty .empty-trait.empty)

(define-public (foo (empty-contracts (tuple (empty <empty>))))
  (ok true)
)
