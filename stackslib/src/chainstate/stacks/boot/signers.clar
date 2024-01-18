(define-data-var stackerdb-signer-slots (list 4000 { signer: principal, num-slots: uint }) (list))

(define-private (stackerdb-set-signer-slots (signer-slots (list 4000 { signer: principal, num-slots: uint })))
	(begin
		(print signer-slots)
		(ok (var-set stackerdb-signer-slots signer-slots))
	)
)

(define-read-only (stackerdb-get-signer-slots)
	(ok (var-get stackerdb-signer-slots))
)

(define-read-only (stackerdb-get-config)
	(ok
		{
		chunk-size: u4096,
		write-freq: u0,
		max-writes: u4096,
		max-neighbors: u32,
		hint-replicas: (list)
		}
	)
)
