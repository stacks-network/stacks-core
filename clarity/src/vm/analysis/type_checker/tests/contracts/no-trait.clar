(define-trait circular (
  ;; trying to define recursive trait by referencing
  ;; trait to be defined later
  (circular (<trait-to-be-defined-later>) (response bool bool))
))
