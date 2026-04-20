;; A constant whose value is a conditional over literal contract principals.
;; The type checker currently rejects this with ExpectedCallableType(PrincipalType)
;; because the `if` expression types to PrincipalType, not CallableType.
;; Future work: the type checker should accept this, since all branches are
;; statically-known contract principals.

(define-constant use-impl-a true)
(define-constant target (if use-impl-a .impl-math-trait .impl-math-trait))

(define-public (call-add)
  (contract-call? target add u1 u2)
)
