(define-trait circular1 (
  (circular (<circular2>) (response bool bool))
))

(define-trait circular2 (
  (circular (<circular1>) (response bool bool))
))
