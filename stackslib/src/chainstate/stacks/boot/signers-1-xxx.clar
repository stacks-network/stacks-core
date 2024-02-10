;; A StackerDB for a specific message type for signer set 1.
;; The contract name indicates which -- it has the form `signers-1-{:message_id}`.

(define-read-only (stackerdb-get-signer-slots)
    (contract-call? .signers stackerdb-get-signer-slots-page u1))

(define-read-only (stackerdb-get-config)
    (contract-call? .signers stackerdb-get-config))
