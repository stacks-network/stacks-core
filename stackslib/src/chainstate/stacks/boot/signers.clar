(define-data-var last-set-cycle uint u0)
(define-data-var stackerdb-signer-slots (list 4000 { signer: principal, num-slots: uint }) (list))
(define-map cycle-set-height uint uint)
(define-constant MAX_WRITES u340282366920938463463374607431768211455)
(define-constant CHUNK_SIZE (* u2 u1024 u1024))

(define-private (stackerdb-set-signer-slots 
                   (signer-slots (list 4000 { signer: principal, num-slots: uint }))
                   (reward-cycle uint)
                   (set-at-height uint))
	(begin
        (map-set cycle-set-height reward-cycle set-at-height)
        (var-set last-set-cycle reward-cycle)
		(ok (var-set stackerdb-signer-slots signer-slots))))

(define-read-only (stackerdb-get-signer-slots)
	(ok (var-get stackerdb-signer-slots)))

(define-read-only (stackerdb-get-signer-by-index (signer-index uint))
	(ok (element-at (var-get stackerdb-signer-slots) signer-index))
)

(define-read-only (stackerdb-get-config)
	(ok
		{ chunk-size: CHUNK_SIZE,
		  write-freq: u0,
		  max-writes: MAX_WRITES,
		  max-neighbors: u32,
		  hint-replicas: (list) }
	))

(define-read-only (stackerdb-get-last-set-cycle)
	(ok (var-get last-set-cycle)))