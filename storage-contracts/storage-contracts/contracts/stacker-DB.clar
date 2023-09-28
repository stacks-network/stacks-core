;; Pending deposit/peg-in requests
;; What data will go here? Need info from signers

(define-constant err-unauthorised (err u1000))


;; Definitions
;; Deposit/Peg-in requests (btc -> sbtc)
(define-data-var deposit-requests-pending uint u0)
(define-map deposit-requests uint
	{
	value: uint,
	sender: { version: (buff 1), hashbytes: (buff 32) },
	destination: principal,
	unlock-script: (buff 128),
	burn-height: uint,
	expiry-burn-height: uint
	})


;; Withdrawal/peg-out requests (sbtc -> btc)
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



;; Insert functions
(define-public (insert-pending-deposit (value uint) (sender { version: (buff 1), hashbytes: (buff 32) }) (destination principal) (unlock-script (buff 128)) (burn-height uint) (expiry-burn-height uint))
    (let (

        )

        ;; Assert that contract-caller is .sbtc contract
        (ok (asserts! (is-eq contract-caller .sbtc) err-unauthorised))

        ;; Do we need amount validation?
        ;; Do we need Bitcoin address validation here?

    )
)

(define-public (insert-pending-withdrawal (value uint) (sender principal) (destination { version: (buff 1), hashbytes: (buff 32) }) (unlock-script (buff 128)) (burn-height uint) (expiry-burn-height uint))
    (let (

        )

        ;; Assert that contract-caller is .sbtc contract
        (ok (asserts! (is-eq contract-caller .sbtc) err-unauthorised))

        ;; Do we need amount validation?
        ;; Do we need Bitcoin address validation here?

    )
)