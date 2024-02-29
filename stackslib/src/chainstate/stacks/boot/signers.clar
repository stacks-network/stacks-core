(define-data-var last-set-cycle uint u0)
(define-data-var stackerdb-signer-slots-0 (list 4000 { signer: principal, num-slots: uint }) (list))
(define-data-var stackerdb-signer-slots-1 (list 4000 { signer: principal, num-slots: uint }) (list))
(define-map cycle-set-height uint uint)
(define-constant MAX_WRITES u4294967295)
(define-constant CHUNK_SIZE (* u2 u1024 u1024))
(define-constant ERR_NO_SUCH_PAGE u1)
(define-constant ERR_CYCLE_NOT_SET u2)

(define-map cycle-signer-set uint (list 4000 { signer: principal, weight: uint }))

;; Called internally by the Stacks node.
;; Stores the stackerdb signer slots for a given reward cycle.
;; Since there is one stackerdb per signer message, the `num-slots` field will always be u1.
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

;; Called internally by the Stacks node.
;; Sets the list of signers and weights for a given reward cycle.
(define-private (set-signers
                 (reward-cycle uint)
                 (signers (list 4000 { signer: principal, weight: uint })))
     (begin
      (asserts! (is-eq (var-get last-set-cycle) reward-cycle) (err ERR_CYCLE_NOT_SET))
      (ok (map-set cycle-signer-set reward-cycle signers))))

;; Get the list of signers and weights for a given reward cycle.
(define-read-only (get-signers (cycle uint))
     (map-get? cycle-signer-set cycle))

;; called by .signers-(0|1)-xxx contracts to get the signers for their respective signing sets
(define-read-only (stackerdb-get-signer-slots-page (page uint))
    (if (is-eq page u0)     (ok (var-get stackerdb-signer-slots-0))
        (if (is-eq page u1)  (ok (var-get stackerdb-signer-slots-1))
            (err ERR_NO_SUCH_PAGE))))

;; Get a signer's signing weight by a given index.
;; Used by other contracts (e.g. the voting contract) 
(define-read-only (get-signer-by-index (cycle uint) (signer-index uint))
	(ok (element-at (unwrap! (map-get? cycle-signer-set cycle) (err ERR_CYCLE_NOT_SET)) signer-index)))

;; called by .signers-(0|1)-xxx contracts
;; NOTE: the node may ignore `write-freq`, since not all stackerdbs will be needed at a given time
(define-read-only (stackerdb-get-config)
	(ok
		{ chunk-size: CHUNK_SIZE,
		  write-freq: u0, 
		  max-writes: MAX_WRITES,
		  max-neighbors: u32,
		  hint-replicas: (list ) }
	))

(define-read-only (get-last-set-cycle)
	(ok (var-get last-set-cycle)))
