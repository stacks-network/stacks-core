;;
;; @contract voting for the aggregate public key
;;

;; maps dkg round and signer to proposed aggregate public key
(define-map votes {reward-cycle: uint, round: uint, signer: principal} {aggregate-public-key: (buff 33), reward-slots: uint})
;; maps dkg round and aggregate public key to weights of signers supporting this key so far
(define-map tally {reward-cycle: uint, round: uint, aggregate-public-key: (buff 33)} uint)
;; maps aggregate public keys to rewards cycles and rounds
(define-map used-aggregate-public-keys (buff 33) {reward-cycle: uint, round: uint})

(define-constant err-signer-index-mismatch (err u10000))
(define-constant err-invalid-signer-index (err u10001))
(define-constant err-out-of-voting-window (err u10002))
(define-constant err-old-round (err u10003))
(define-constant err-ill-formed-aggregate-public-key (err u10004))
(define-constant err-duplicate-aggregate-public-key (err u10005))
(define-constant err-duplicate-vote (err u10006))
(define-constant err-invalid-burn-block-height (err u10007))

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
    (var-get state-1))

(define-read-only (burn-height-to-reward-cycle (height uint))
    (/ (- height (get first-burnchain-block-height pox-info)) (get reward-cycle-length pox-info)))

(define-read-only (reward-cycle-to-burn-height (reward-cycle uint))
    (+ (* reward-cycle (get reward-cycle-length pox-info)) (get first-burnchain-block-height pox-info)))

(define-read-only (current-reward-cycle)
    (burn-height-to-reward-cycle burn-block-height))

(define-read-only (get-last-round (reward-cycle uint))
    (map-get? rounds reward-cycle))

(define-read-only (get-vote (reward-cycle uint) (round uint) (signer principal))
    (map-get? votes {reward-cycle: reward-cycle, round: round, signer: signer}))

(define-read-only (get-tally (reward-cycle uint) (round uint) (aggregate-public-key (buff 33)))
    (map-get? tally {reward-cycle: reward-cycle, round: round, aggregate-public-key: aggregate-public-key}))

(define-read-only (get-signer-slots (signer-index uint) (reward-cycle uint))
    (let ((height (reward-cycle-to-burn-height reward-cycle)))
            (ok (at-block
                (unwrap! (get-block-info? id-header-hash height) err-invalid-burn-block-height)
                    (get-current-signer-slots signer-index)))))

(define-read-only (get-current-signer-slots (signer-index uint))
    (let ((details (unwrap! (unwrap-panic (contract-call? .signers stackerdb-get-signer-by-index signer-index)) err-invalid-signer-index)))
        (asserts! (is-eq (get signer details) tx-sender) err-signer-index-mismatch)
        (ok (get num-slots details))))

;; aggregate public key must be unique and can be used only in a single cycle-round pair
(define-read-only (is-valid-aggregated-public-key (key (buff 33)) (dkg-id {reward-cycle: uint, round: uint}))
    (is-eq (default-to dkg-id (map-get? used-aggregate-public-keys key)) dkg-id))

(define-read-only (is-in-prepare-phase (height uint))
    (< (mod (+ (- height (get first-burnchain-block-height pox-info))
                (get prepare-cycle-length pox-info))
             (get reward-cycle-length pox-info)
            )
        (get prepare-cycle-length pox-info)))

(define-private (is-in-voting-window (height uint) (reward-cycle uint))
    (let ((last-cycle (unwrap-panic (contract-call? .signers stackerdb-get-last-set-cycle))))
        (and (is-eq last-cycle reward-cycle)
            (is-in-prepare-phase height))))

(define-public (vote-for-aggregate-public-key (signer-index uint) (key (buff 33)) (round uint))
    (let ((reward-cycle (+ u1 (burn-height-to-reward-cycle burn-block-height)))
            (tally-key {reward-cycle: reward-cycle, round: round, aggregate-public-key: key})
            ;; one slot, one vote
            (num-slots (try! (get-current-signer-slots signer-index)))
            (new-total (+ num-slots (default-to u0 (map-get? tally tally-key)))))
        (asserts! (is-in-voting-window burn-block-height reward-cycle) err-out-of-voting-window)
        (asserts! (>= round (default-to u0 (map-get? rounds reward-cycle))) err-old-round)
        (asserts! (is-eq (len key) u33) err-ill-formed-aggregate-public-key)
        (asserts! (is-valid-aggregated-public-key key {reward-cycle: reward-cycle, round: round}) err-duplicate-aggregate-public-key)
        (asserts! (map-insert votes {reward-cycle: reward-cycle, round: round, signer: tx-sender} {aggregate-public-key: key, reward-slots: num-slots}) err-duplicate-vote)
        (map-set tally tally-key new-total)
        (map-set used-aggregate-public-keys key {reward-cycle: reward-cycle, round: round})
        (update-last-round reward-cycle round)
        (print { 
            event: "voted", 
            signer: tx-sender, 
            reward-cycle: reward-cycle, 
            round: round, 
            key: key, 
            new-total: new-total })
        (ok true)))

(define-private (update-last-round (reward-cycle uint) (round uint))
    (match (map-get? rounds reward-cycle)
        last-round (and (> round last-round) (map-set rounds reward-cycle round))
        (map-set rounds reward-cycle round)))