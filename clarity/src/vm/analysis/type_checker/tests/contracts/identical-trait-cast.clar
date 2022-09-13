(use-trait empty      .empty-trait.empty)
(use-trait empty-copy .empty-trait-copy.empty)

(define-public (use-empty (empty-contract <empty>))
  (ok true)
)

(define-public (use-empty-copy (empty-contract <empty-copy>))
  (use-empty empty-contract)
)
