(define-public (test-burn-height-to-reward-cycle)
	(begin 
		(asserts! (is-eq u2 (contract-call? .pox-4 burn-height-to-reward-cycle u2100)) (err "Burn height 2100 should have been reward cycle 2"))
		(asserts! (is-eq u3 (contract-call? .pox-4 burn-height-to-reward-cycle u3150)) (err "Burn height 3150 should have been reward cycle 2"))
		(ok true)
	)
)

(define-public (test-reward-cycle-to-burn-height)
	(begin 
		(asserts! (is-eq u10500 (contract-call? .pox-4 reward-cycle-to-burn-height u10)) (err "Cycle 10 height should have been at burn height 10500"))
		(asserts! (is-eq u18900 (contract-call? .pox-4 reward-cycle-to-burn-height u18)) (err "Cycle 18 height should have been at burn height 18900"))
		(ok true)
	)
)

(define-public (test-get-stacker-info-none)
	(begin 
		(asserts! (is-none (contract-call? .pox-4 get-stacker-info tx-sender)) (err "By default, tx-sender should not have stacker info"))
		(ok true)
	)
)


(define-private (check-pox-addr-version-iter (input (buff 1)))
	(contract-call? .pox-4 check-pox-addr-version input)
)

(define-public (test-check-pox-addr-version)
	(begin
		(asserts! (is-eq (map check-pox-addr-version-iter byte-list)
			(list
				true  true  true  true  true  true  true  false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
				false false false false false false false false false false false false false false false false
			))
			(err "Only the first 6 versions should be valid")
		)
		(ok true)
	)
)

(define-private (check-pox-addr-hashbytes-iter (test-length uint) (version (buff 1)))
	(contract-call? .pox-4 check-pox-addr-hashbytes version (unwrap-panic (as-max-len? (unwrap-panic (slice? byte-list u0 test-length)) u32)))
)

(define-public (test-invalid-pox-addr-hashbytes-length)
	(let (
		(test-lengths (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16 u17 u18 u19 u20 u21 u22 u23 u24 u25 u26 u27 u28 u29 u30 u31 u32))
		(length-20-valid (list
			false false false false false false false false false false false false false false false false
			false false false false true  false false false false false false false false false false false false
			))
		(length-32-valid (list
			false false false false false false false false false false false false false false false false
			false false false false false false false false false false false false false false false false true
			))
		(length-all-invalid (list
			false false false false false false false false false false false false false false false false
			false false false false false false false false false false false false false false false false false
			))
		)
		(asserts! (is-eq (map check-pox-addr-hashbytes-iter test-lengths (buff-repeat 0x00 (len test-lengths))) length-20-valid)
			(err "Only length 20 should be valid for version 0x00")
		)
		(asserts! (is-eq (map check-pox-addr-hashbytes-iter test-lengths (buff-repeat 0x01 (len test-lengths))) length-20-valid)
			(err "Only length 20 should be valid for version 0x01")
		)
		(asserts! (is-eq (map check-pox-addr-hashbytes-iter test-lengths (buff-repeat 0x02 (len test-lengths))) length-20-valid)
			(err "Only length 20 should be valid for version 0x02")
		)
		(asserts! (is-eq (map check-pox-addr-hashbytes-iter test-lengths (buff-repeat 0x03 (len test-lengths))) length-20-valid)
			(err "Only length 20 should be valid for version 0x03")
		)
		(asserts! (is-eq (map check-pox-addr-hashbytes-iter test-lengths (buff-repeat 0x04 (len test-lengths))) length-20-valid)
			(err "Only length 20 should be valid for version 0x04")
		)
		(asserts! (is-eq (map check-pox-addr-hashbytes-iter test-lengths (buff-repeat 0x05 (len test-lengths))) length-32-valid)
			(err "Only length 32 should be valid for version 0x05")
		)
		(asserts! (is-eq (map check-pox-addr-hashbytes-iter test-lengths (buff-repeat 0x06 (len test-lengths))) length-32-valid)
			(err "Only length 32 should be valid for version 0x06")
		)
		(asserts! (is-eq (map check-pox-addr-hashbytes-iter test-lengths (buff-repeat 0x07 (len test-lengths))) length-all-invalid)
			(err "No length should be valid for version 0x07")
		)
		(ok true)
	)
)

(define-private (check-pox-lock-period-iter (period uint))
	(contract-call? .pox-4 check-pox-lock-period period)
)

(define-public (test-check-pox-lock-period)
	(let ((actual (map check-pox-lock-period-iter (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13))))
		(asserts! (is-eq
			actual
			(list false true true true true true true true true true true true true false))
			(err {err: "Expected only lock periods 1 to 12 to be valid", actual: actual})
		)
		(ok true)
	)
)

(define-public (test-get-total-ustx-stacked)
	(begin 
		(asserts! (is-eq (contract-call? .pox-4 get-total-ustx-stacked u1) u0) (err "Total ustx stacked should be 0"))
		(ok true)
	)
)


(define-private (repeat-iter (a (buff 1)) (repeat {i: (buff 1), o: (buff 33)}))
	{i: (get i repeat), o: (unwrap-panic (as-max-len? (concat (get i repeat) (get o repeat)) u33))}
)

(define-read-only (buff-repeat (repeat (buff 1)) (times uint))
	(get o (fold repeat-iter (unwrap-panic (slice? byte-list u0 times)) {i: repeat, o: 0x}))
)

(define-constant byte-list 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff)