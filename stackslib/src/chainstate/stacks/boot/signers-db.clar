;; A StackerDB for a specific message type for a specific signer set.
;; The contract name indicates which -- it has the form `signers-{:signer_set}-{:message_id}`.

(define-read-only (stackerdb-get-signer-slots)
    (contract-call? .signers stackerdb-get-signer-slots))

(define-read-only (stackerdb-get-config)
    (contract-call? .signers stackerdb-get-config))
