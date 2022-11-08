(use-trait a-alias .a-trait.a)

(define-trait a (
  (do-that () (response bool bool))
))

(define-public (call-do-it (a-contract <a-alias>))
  (contract-call? a-contract do-it)
)
