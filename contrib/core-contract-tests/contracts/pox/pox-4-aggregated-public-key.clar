;; @contract voting for the aggregated public key

;; maps dkg round and signer to proposed aggregated public key
(define-map votes {reward-cycle: uint, round: uint, signer: (buff 33)} (buff 33))
;; maps dkg rount and aggregated public key to weights of signers supporting this key so far
(define-map tally {reward-cycle: uint, round: uint, aggregate-public-key: (buff 33)} uint)

(define-constant err-not-allowed (err u10000))
(define-constant err-incorrect-reward-cycle (err u10001))
(define-constant err-incorrect-round (err u10002))
(define-constant err-invalid-aggregated-public-key (err u10003))
(define-constant err-duplicate-vote (err u10004))
(define-constant err-invalid-burn-block-height (err u10005))

(define-data-var last-round uint u0)
(define-data-var state {reward-cycle: uint, round: uint, aggregated-public-key: (optional (buff 33)),
    weight: uint}  {reward-cycle: u0, round: u0, aggregated-public-key: none, weight: u0}) 
;; get info by burn block height
(define-read-only (get-info (height uint))
    (ok (at-block (unwrap! (get-block-info? id-header-hash height) err-invalid-burn-block-height) (var-get state))))

(define-read-only (get-signer-public-key (signer principal) (reward-cycle uint))
    (some 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20))

(define-read-only (get-signer-weight (signer-public-key (buff 33)) (reward-cycle uint))
    u1000000000000)

(define-read-only (current-reward-cycle)
    u0)

(define-public (vote-for-aggreated-public-key (key (buff 33)) (reward-cycle uint) (round uint) (tapleaves (list 4001 (buff 33))))
    (let ((signer-public-key (unwrap! (get-signer-public-key tx-sender reward-cycle) err-not-allowed))
            (weight (get-signer-weight signer-public-key reward-cycle))
            (tally-key {reward-cycle: reward-cycle, round: round, aggregate-public-key: key})
            (new-weight (+ weight (default-to u0 (map-get? tally tally-key))))
            (current-round (var-get last-round)))
        (asserts! (is-eq reward-cycle (current-reward-cycle)) err-incorrect-reward-cycle)
        (asserts! (is-eq round current-round) err-incorrect-round)
        (asserts! (is-eq (len key) u33) err-invalid-aggregated-public-key)
        (asserts! (map-set votes {reward-cycle: reward-cycle, round: round, signer: signer-public-key} key) err-duplicate-vote)
        (map-set tally tally-key new-weight)
        (ok true)))