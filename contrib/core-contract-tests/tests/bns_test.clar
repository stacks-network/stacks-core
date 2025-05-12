(define-public (test-can-receive-name-none)
	(begin
		(asserts!
			(is-eq (ok true) (contract-call? .bns can-receive-name tx-sender))
			(err "Should be able to receive a name")
		)
		(ok true)
	)
)