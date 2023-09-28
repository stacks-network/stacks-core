(define-data-var current-cycle-signer-slots (list 10 {signer: principal, num-slots: uint}) (list {signer: tx-sender, num-slots: u10}))
(define-data-var previous-cycle-signer-slots (list 10 {signer: principal, num-slots: uint}) (list ))

 (define-read-only (stackerdb-get-config)
            (ok {
                chunk-size: u4096,
                write-freq: u0,
                max-writes: u4096,
                max-neighbors: u32,
                hint-replicas: (list )
            }))