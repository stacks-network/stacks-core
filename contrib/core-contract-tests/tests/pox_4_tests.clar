(define-constant mock-pox-reward-wallet-1 { version: 0x06, hashbytes: 0x0011223344556699001122334455669900112233445566990011223344556699 })
(define-constant mock-pox-reward-wallet-invalid { version: 0x06, hashbytes: 0x00112233445566990011223344556699001122334455669900112233445566 })
(define-constant mock-pox-hashbytes-invalid 0x00112233445566990011223344556699001122334455669900112233445566)

(define-public (test-mock-set-stx-account)
	(begin 
		(unwrap! (contract-call? .pox-4 mock-set-stx-account 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5 {locked: u1, unlock-height: u2100, unlocked: u0}) (err u111))
		(asserts! (is-eq u1 (get locked (contract-call? .pox-4 get-stx-account 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5))) (err u112))
		(ok true)))

(define-public (test-get-mocked-stx-account)
	(begin 
		(asserts! (is-eq u0 (get unlock-height (contract-call? .pox-4 get-stx-account 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5))) (err u111))
		(ok true)))

(define-public (test-burn-height-to-reward-cycle)
	(begin 
		(asserts! (is-eq u1 (contract-call? .pox-4 burn-height-to-reward-cycle u2099)) (err u111))
		(ok true)))

(define-public (test-reward-cycle-to-burn-height)
	(begin 
		(asserts! (is-eq u0 (contract-call? .pox-4 reward-cycle-to-burn-height u0)) (err u111))
		(ok true)))

(define-public (test-get-stacker-info-none)
	(begin 
		(asserts! (is-none (contract-call? .pox-4 get-stacker-info tx-sender)) (err u111))
		(ok true)))

(define-public (test-invalid-pox-addr-version)
	(let
		((actual (contract-call? .pox-4 check-pox-addr-version 0x07))) 
		(asserts! (not actual) (err u111))
		(ok true)))

(define-public (test-invalid-pox-addr-hashbytes-length)
	(let
		((actual (contract-call? .pox-4 check-pox-addr-hashbytes 0x00 mock-pox-hashbytes-invalid))) 
		(asserts! (not actual) (err u111))
		(ok true)))

(define-public (test-invalid-lock-height-too-low)
	(let
		((actual (contract-call? .pox-4 check-pox-lock-period u0)))
		(asserts! (not actual) (err u111))
		(ok true)))

(define-public (test-invalid-lock-height-too-high)
	(let
		((actual (contract-call? .pox-4 check-pox-lock-period u13)))
		(asserts! (not actual) (err u111))
		(ok true)))

(define-public (test-get-total-ustx-stacked)
	(begin 
		;; @continue
		(asserts! (is-eq (contract-call? .pox-4 get-total-ustx-stacked u1) u0) (err u111))
		(ok true)))