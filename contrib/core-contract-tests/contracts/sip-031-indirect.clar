;; This is a wrapper contract to test calling `.sip-031`
;; from an outside contract.

(define-public (update-recipient (new-recipient principal))
  (contract-call? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031 update-recipient new-recipient)
)