(define-data-var last-set-cycle uint u0)
(define-data-var stackerdb-signer-slots-0 (list 4000 { signer: principal, num-slots: uint }) (list))
(define-data-var stackerdb-signer-slots-1 (list 4000 { signer: principal, num-slots: uint }) (list))
(define-map cycle-set-height uint uint)
(define-constant MAX_WRITES u340282366920938463463374607431768211455)
(define-constant CHUNK_SIZE (* u2 u1024 u1024))
(define-constant ERR_NO_SUCH_PAGE u1)
(define-constant ERR_CYCLE_NOT_SET u2)
(define-map cycle-signer-set uint (list 4000 { signer: principal, weight: uint }))

(define-private (stackerdb-set-signer-slots 
                   (signer-slots (list 4000 { signer: principal, num-slots: uint }))
                   (reward-cycle uint)
                   (set-at-height uint))
	(let ((cycle-mod (mod reward-cycle u2)))
        (map-set cycle-set-height reward-cycle set-at-height)
        (var-set last-set-cycle reward-cycle)
        (if (is-eq cycle-mod u0)
            (ok (var-set stackerdb-signer-slots-0 signer-slots))
            (ok (var-set stackerdb-signer-slots-1 signer-slots)))))

(define-private (stackerdb-set-signers
                 (reward-cycle uint)
                 (signers (list 4000 { signer: principal, weight: uint })))
     (begin
      (asserts! (is-eq (var-get last-set-cycle) reward-cycle) (err ERR_CYCLE_NOT_SET))
      (ok (map-set cycle-signer-set reward-cycle signers))))

(define-read-only (get-signers (cycle uint))
     (map-get? cycle-signer-set cycle))

(define-read-only (stackerdb-get-page-count) (ok u2))

(define-read-only (stackerdb-get-signer-slots (page uint))
    (if (is-eq page u0)      (ok (var-get stackerdb-signer-slots-0))
        (if (is-eq page u1)  (ok (var-get stackerdb-signer-slots-1))
        (err ERR_NO_SUCH_PAGE))))

(define-read-only (stackerdb-get-signer-by-index (cycle uint) (signer-index uint))
	(ok (element-at (unwrap! (map-get? cycle-signer-set cycle) (err ERR_CYCLE_NOT_SET)) signer-index)))

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