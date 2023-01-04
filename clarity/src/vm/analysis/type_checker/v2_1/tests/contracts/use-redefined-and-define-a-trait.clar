(use-trait a-alias .a-trait.a)

(define-trait a (
  (do-that () (response bool bool))
))

(define-public (call-do-that (a-contract <a-alias>))
  (contract-call? a-contract do-that)
)

(define-public (call-do-that-2 (a-contract <a>))
  (contract-call? a-contract do-that)
)
