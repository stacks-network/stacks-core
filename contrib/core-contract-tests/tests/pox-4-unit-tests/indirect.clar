(define-public (delegate-stx (amount-ustx uint)
                             (delegate-to principal)
                             (until-burn-ht (optional uint))
                             (pox-addr (optional { version: (buff 1), hashbytes: (buff 32) })))
  (contract-call? 'ST000000000000000000002AMW42H.pox-4 delegate-stx amount-ustx delegate-to until-burn-ht pox-addr)
)

(define-public (revoke-delegate-stx)
  (contract-call? 'ST000000000000000000002AMW42H.pox-4 revoke-delegate-stx)
)

(define-public (allow-contract-caller (caller principal) (until-burn-ht (optional uint)))
  (contract-call? 'ST000000000000000000002AMW42H.pox-4 allow-contract-caller caller until-burn-ht)
)

(define-public (disallow-contract-caller (caller principal))
  (contract-call? 'ST000000000000000000002AMW42H.pox-4 disallow-contract-caller caller)
)
