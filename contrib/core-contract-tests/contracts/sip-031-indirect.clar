;; This is a wrapper contract to test calling `.sip-031`
;; from an outside contract.

(define-public (update-recipient (new-recipient principal))
  (contract-call? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031
    update-recipient new-recipient
  )
)

;; WARNING: This is for testing purposes only.
;; This is not a safe way to call `update-recipient` from an external contract,
;; as it does not perform the necessary authorization checks.
(define-public (update-recipient-as-contract (new-recipient principal))
  (as-contract (contract-call? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031
    update-recipient new-recipient
  ))
)

;; WARNING: This is for testing purposes only.
;; This is not a safe way to call `claim` from an external contract,
;; as it does not perform the necessary authorization checks.
(define-public (claim-as-contract)
  (as-contract (contract-call? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031 claim))
)

;; Helper function to transfer STX within tests
(define-public (transfer-stx
    (amount uint)
    (recipient principal)
  )
  (stx-transfer? amount tx-sender recipient)
)

;; Helper function to get the STX balance of an address
(define-read-only (get-balance (addr principal))
  (stx-get-balance addr)
)
