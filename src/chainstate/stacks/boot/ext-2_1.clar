;; Stacks 2.1 extension contracts.
;; Each function here has a native implementation.
;; The code here serves only to provide the analysis checker with
;; enough information to type-check any contracts that call into it.

;; Get the current epoch ID.
;; The epoch ID is two bytes.
;; * Byte 15 is the major version. This is always 0x02.
;; * Byte 16 is the minor version. This is 0x01 for Stacks 2.1.
;; Future Stacks network upgrades, if they are ever done at all,
;; will return a different epoch ID.
;; This function has a native implementation; it does not actually
;; return (ok u0).
(define-public (get-epoch-id) (ok u0))
