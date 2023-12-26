(use-trait a-alias .use-and-define-a-trait.a)

(define-public (call-do-that (a-contract <a-alias>))
  (contract-call? a-contract do-it)
)
