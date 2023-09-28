;; Pending deposit/peg-in requests
;; What data will go here? Need info from signers
(define-data-var deposit-requests-pending uint u0)
(define-map deposit-requests uint
	{
	value: uint,
	sender: principal,
	destination: { version: (buff 1), hashbytes: (buff 32) },
	unlock-script: (buff 128),
	burn-height: uint,
	expiry-burn-height: uint
	})


;; Pending withdrawal/peg-out requests
(define-data-var withdrawal-requests-pending uint u0)
(define-map withdrawal-requests uint
	{
	value: uint,
	sender: principal,
	destination: { version: (buff 1), hashbytes: (buff 32) },
	unlock-script: (buff 128),
	burn-height: uint,
	expiry-burn-height: uint
	})


;; Handoff requests
;; Is-DKG-stale