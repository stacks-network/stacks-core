;;
;; @contract voting for the aggregate public key
;;

;; maps dkg round and signer to proposed aggregate public key
(define-map votes {reward-cycle: uint, round: uint, signer: principal} {aggregate-public-key: (buff 33), reward-slots: uint})
;; maps dkg round and aggregate public key to weights of signers supporting this key so far
(define-map tally {reward-cycle: uint, round: uint, aggregate-public-key: (buff 33)} uint)
;; maps aggregate public keys to rewards cycles and rounds
(define-map used-aggregate-public-keys (buff 33) {reward-cycle: uint, round: uint})

(define-constant err-not-allowed (err u10000))
(define-constant err-incorrect-reward-cycle (err u10001))
(define-constant err-old-round (err u10002))
(define-constant err-invalid-aggregate-public-key (err u10003))
(define-constant err-duplicate-aggregate-public-key (err u10004))
(define-constant err-duplicate-vote (err u10005))
(define-constant err-invalid-burn-block-height (err u10006))

(define-constant pox-info
    (unwrap-panic (contract-call? .pox-4 get-pox-info)))

;; maps reward-cycle ids to last round
(define-map rounds uint uint)

(define-data-var state-1 {reward-cycle: uint, round: uint, aggregate-public-key: (optional (buff 33)),
    total-votes: uint}  {reward-cycle: u0, round: u0, aggregate-public-key: none, total-votes: u0})
(define-data-var state-2 {reward-cycle: uint, round: uint, aggregate-public-key: (optional (buff 33)),
    total-votes: uint}  {reward-cycle: u0, round: u0, aggregate-public-key: none, total-votes: u0})

;; get voting info by burn block height
(define-read-only (get-info (height uint))
    (ok (at-block (unwrap! (get-block-info? id-header-hash height) err-invalid-burn-block-height) (get-current-info))))

;; get current voting info
(define-read-only (get-current-info)
    (if (is-eq (/ (current-reward-cycle) u2) u0) (var-get state-1) (var-get state-2)))

(define-read-only (burn-height-to-reward-cycle (height uint))
    (/ (- height (get first-burnchain-block-height pox-info)) (get reward-cycle-length pox-info)))

(define-read-only (current-reward-cycle)
    (burn-height-to-reward-cycle burn-block-height))
    
(define-read-only (get-last-round (reward-cycle uint))
    (map-get? rounds reward-cycle))

(define-read-only (get-signer-slots (signer principal) (reward-cycle uint))
    (contract-call? .signers get-signer-slots signer reward-cycle))

;; aggregate public key must be unique and can be used only in a single cycle-round pair
(define-read-only (is-valid-aggregated-public-key (key (buff 33)) (dkg-id {reward-cycle: uint, round: uint}))
    (is-eq (default-to dkg-id (map-get? used-aggregate-public-keys key)) dkg-id))

(define-public (vote-for-aggregate-public-key (key (buff 33)) (reward-cycle uint) (round uint))
    (let ((tally-key {reward-cycle: reward-cycle, round: round, aggregate-public-key: key})
            ;; one slot, one vote
            (num-slots (unwrap! (get-signer-slots tx-sender reward-cycle) err-not-allowed))
            (new-total (+ num-slots (default-to u0 (map-get? tally tally-key)))))
        (asserts! (is-eq reward-cycle (current-reward-cycle)) err-incorrect-reward-cycle)
        (asserts! (>= round (default-to u0 (map-get? rounds reward-cycle))) err-old-round)
        (asserts! (is-eq (len key) u33) err-invalid-aggregate-public-key)
        (asserts! (is-valid-aggregated-public-key key {reward-cycle: reward-cycle, round: round}) err-duplicate-aggregate-public-key)
        (asserts! (map-insert votes {reward-cycle: reward-cycle, round: round, signer: tx-sender} {aggregate-public-key: key, reward-slots: num-slots}) err-duplicate-vote)
        (map-set tally tally-key new-total)
        (map-set used-aggregate-public-keys key {reward-cycle: reward-cycle, round: round})
        (update-last-round reward-cycle round)
        (print "voted")
        (ok true)))

(define-private (update-last-round (reward-cycle uint) (round uint))
    (match (map-get? rounds reward-cycle)
        last-round (and (> round last-round) (map-set rounds reward-cycle round))
        (map-set rounds reward-cycle round)))