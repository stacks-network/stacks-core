(use-trait empty .empty-trait.empty)

(define-read-only (use-empty (empty-contract <empty>))
  (ok true)
)

(define-read-only (use-empty-2 (empty-contract <empty>))
  (use-empty empty-contract)
)
