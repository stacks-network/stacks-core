;; Contains functions used in testing the hyperchains contract.

;; Returns the `id-header-hash` of the chain tip. This is used for `clarinet` tests
;; where we do not yet have access to this value through the API.
(define-read-only (get-id-header-hash)
    (ok (unwrap! (get-block-info? id-header-hash (- block-height u1)) (err u0)))
)
