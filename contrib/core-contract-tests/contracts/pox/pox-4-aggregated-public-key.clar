;; @contract voting for the aggregated public key

;; maps dkg round and signer to proposed aggregated public key
(define-map votes {reward-cycle: uint, round: uint, signer: principal} (buff 33))
;; maps dkg rount and aggregated public key to weights of signers supporting this key so far
(define-map tally {reward-cycle: uint, round: uint, aggregate-public-key: (buff 33)} uint)

(define-constant err-not-allowed (err u10000))
(define-constant err-incorrect-reward-cycle (err u10001))
(define-constant err-incorrect-round (err u10002))
(define-constant err-invalid-aggregated-public-key (err u10003))
(define-constant err-duplicate-vote (err u10004))

(define-data-var last-round uint 0)

(define-constant UNINITIALIZED {reward-cycle: 0, round: 0, aggregate-public-key: (none), weight: 0})
(define-data-var state {
    reward-cycle: uint,
    round: uint,
    aggregate-public-key: (some (buff 33)),
    weights: uint}
    UNINITIALIZED)

;; get info by burn block height
(define-read-only (get-info (height uint))
    (at-block (get-block-info id-header-hash height) (var-get state)))

(define-public vote-for-aggreated-public-key (key (buff 33)) (reward-cycle uint) (round uint) (tapleaves (list 4001 (buff 33)))
    (let ((signer-public-key (unwrap! (get-signer-public-key tx-sender reward-cycle) err-not-allowed))
            (weight (get-signer-weight signer-public-key reward-cycle))
            (tally-key {reward-cycle: reward-cycle, round: round, aggregate-public-key: key})
            (new-weight (+ weight (default-to u0 (map-get? tally tally-key)))))
        (asserts! (is-eq reward-cycle (current-reward-cycle)) err-incorrect-reward-cycle)
        (asserts! (is-eq round (current-round)) err-incorrect-round)
        (asserts! (is-eq (len key) 33) err-invalid-aggregated-public-key)
        (asserts! (map-set votes {reward-cycle: reward-cycle, round: round, signer: signer-public-key} key) err-duplicate-vote)
        (map-set tally tally-key (+ current-weight weight))))