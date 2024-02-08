;;
;; @contract voting for the aggregate public key
;;

;; maps dkg round and signer to proposed aggregate public key
(define-map votes {reward-cycle: uint, round: uint, signer: principal} {aggregate-public-key: (buff 33), reward-slots: uint})
;; maps dkg round and aggregate public key to weights of signers supporting this key so far
(define-map tally {reward-cycle: uint, round: uint, aggregate-public-key: (buff 33)} uint)
;; maps aggregate public keys to rewards cycles and rounds
(define-map used-aggregate-public-keys (buff 33) {reward-cycle: uint, round: uint})

(define-constant ERR_SIGNER_INDEX_MISMATCH 1)
(define-constant ERR_INVALID_SIGNER_INDEX 2)
(define-constant ERR_OUT_OF_VOTING_WINDOW 3)
(define-constant ERR_OLD_ROUND 4)
(define-constant ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY 5)
(define-constant ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY 6)
(define-constant ERR_DUPLICATE_VOTE 7)
(define-constant ERR_INVALID_BURN_BLOCK_HEIGHT 8)

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
    (ok (at-block (unwrap! (get-block-info? id-header-hash height) (err ERR_INVALID_BURN_BLOCK_HEIGHT)) (get-current-info))))

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

(define-read-only (get-current-signer-weight (signer-index uint))
    (let ((cycle (+ u1 (burn-height-to-reward-cycle burn-block-height))))
      (get-signer-weight signer-index cycle)))

(define-read-only (get-signer-weight (signer-index uint) (reward-cycle uint))
    (let ((details (unwrap! (try! (contract-call? .signers get-signer-by-index reward-cycle signer-index)) (err (to-uint ERR_INVALID_SIGNER_INDEX)))))
        (asserts! (is-eq (get signer details) tx-sender) (err (to-uint ERR_SIGNER_INDEX_MISMATCH)))
        (ok (get weight details))))

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
    (let ((last-cycle (unwrap-panic (contract-call? .signers get-last-set-cycle))))
        (and (is-eq last-cycle reward-cycle)
            (is-in-prepare-phase height))))

;; Signer vote for the aggregate public key of the next reward cycle
;;  The vote happens in the prepare phase of the current reward cycle but may be ran more than
;;  once resulting in different 'rounds.' Each signer vote is based on the weight of stacked
;;  stx tokens & fetched from the .signers contract. The vote is ran until the consensus 
;;  threshold of 70% for a specific aggregate public key is reached. 
(define-public (vote-for-aggregate-public-key (signer-index uint) (key (buff 33)) (round uint))
    (let ((reward-cycle (+ u1 (burn-height-to-reward-cycle burn-block-height)))
            (tally-key {reward-cycle: reward-cycle, round: round, aggregate-public-key: key})
            ;; vote by signer weight
            (num-weight (try! (get-current-signer-weight signer-index)))
            (new-total (+ num-weight (default-to u0 (map-get? tally tally-key)))))
        ;; Check we're in the prepare phase
        (asserts! (is-in-voting-window burn-block-height reward-cycle) (err (to-uint ERR_OUT_OF_VOTING_WINDOW)))
        ;; Check that vote is for latest round in reward cycle
        (asserts! (>= round (default-to u0 (map-get? rounds reward-cycle))) (err (to-uint ERR_OLD_ROUND)))
        ;; Check that the aggregate public key is correct length
        (asserts! (is-eq (len key) u33) (err (to-uint ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY)))
        ;; Check that aggregate public key has not been used before
        (asserts! (is-valid-aggregated-public-key key {reward-cycle: reward-cycle, round: round}) (err (to-uint ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY)))
        ;; Check that signer hasn't voted in reward-cycle & round
        (asserts! (map-insert votes {reward-cycle: reward-cycle, round: round, signer: tx-sender} {aggregate-public-key: key, reward-slots: num-weight}) (err (to-uint ERR_DUPLICATE_VOTE)))
        ;; Update tally aggregate public key candidate
        (map-set tally tally-key new-total)
        ;; Update used aggregate public keys
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
