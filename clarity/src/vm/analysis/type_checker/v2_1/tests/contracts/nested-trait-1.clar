(use-trait empty .empty-trait.empty)

(define-public (foo (empty-contracts (list 2 <empty>)))
  (ok true)
)
