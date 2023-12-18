;; This contract governs a StackerDB instance in which the current and previous
;; miner can send their blocks to Stackers for an aggregate signature.
;; This is a placeholder smart contract, which allows the node to advertize
;; that it replicates the state for this StackerDB while maintaining the power
;; to generate the config and signer slots directly.

;; StackerDB-required method to get the allocation of slots for signers.
;; The values here are ignored.
(define-public (stackerdb-get-signer-slots)
    (ok (list )))

;; StackerDB-required method to get the DB configuration.
;; The values here are ignored.
(define-public (stackerdb-get-config)
    (ok {
        chunk-size: u0,
        write-freq: u0,
        max-writes: u0,
        max-neighbors: u0,
        hint-replicas: (list )
    }))
