;;
;; @contract voting for the aggregate public key
;;

;; maps dkg round and signer to proposed aggregate public key
(define-map votes {reward-cycle: uint, round: uint, signer: principal} {aggregate-public-key: (buff 33), signer-weight: uint})
;; maps dkg round and aggregate public key to weights of signers supporting this key so far
(define-map tally {reward-cycle: uint, round: uint, aggregate-public-key: (buff 33)} uint)
;; maps aggregate public keys to rewards cycles
(define-map used-aggregate-public-keys (buff 33) uint)

(define-constant ERR_SIGNER_INDEX_MISMATCH u1)
(define-constant ERR_INVALID_SIGNER_INDEX u2)
(define-constant ERR_OUT_OF_VOTING_WINDOW u3)
(define-constant ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY u5)
(define-constant ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY u6)
(define-constant ERR_DUPLICATE_VOTE u7)
(define-constant ERR_INVALID_BURN_BLOCK_HEIGHT u8)
(define-constant ERR_FAILED_TO_RETRIEVE_SIGNERS u9)

(define-constant pox-info
    (unwrap-panic (contract-call? .pox-4 get-pox-info)))

;; Threshold consensus (in 3 digit %)
(define-constant threshold-consensus u700)

;; Maps reward-cycle ids to last round
(define-map rounds uint uint)

;; Maps reward-cycle ids to aggregate public key.
(define-map aggregate-public-keys uint (buff 33))

;; Maps reward-cycle id to the total weight of signers. This map is used to
;; cache the total weight of signers for a given reward cycle, so it is not
;; necessary to recalculate it on every vote.
(define-map cycle-total-weight uint uint)

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

(define-read-only (get-candidate-info (reward-cycle uint) (round uint) (candidate (buff 33)))
    {candidate-weight: (default-to u0 (map-get? tally {reward-cycle: reward-cycle, round: round, aggregate-public-key: candidate})),
    total-weight: (map-get? cycle-total-weight reward-cycle)})

(define-read-only (get-tally (reward-cycle uint) (round uint) (aggregate-public-key (buff 33)))
    (map-get? tally {reward-cycle: reward-cycle, round: round, aggregate-public-key: aggregate-public-key}))

(define-read-only (get-current-signer-weight (signer-index uint))
    (let ((cycle (+ u1 (burn-height-to-reward-cycle burn-block-height))))
      (get-signer-weight signer-index cycle)))

(define-read-only (get-signer-weight (signer-index uint) (reward-cycle uint))
    (let ((details (unwrap! (try! (contract-call? .signers get-signer-by-index reward-cycle signer-index)) (err ERR_INVALID_SIGNER_INDEX))))
        (asserts! (is-eq (get signer details) tx-sender) (err ERR_SIGNER_INDEX_MISMATCH))
        (ok (get weight details))))

;; aggregate public key must be unique and can be used only in a single cycle-round pair
(define-read-only (is-valid-aggregate-public-key (key (buff 33)) (reward-cycle uint))
    (is-eq (default-to reward-cycle (map-get? used-aggregate-public-keys key)) reward-cycle))

(define-read-only (is-in-prepare-phase (height uint))
    (< (mod (+ (- height (get first-burnchain-block-height pox-info))
                (get prepare-cycle-length pox-info))
             (get reward-cycle-length pox-info)
            )
        (get prepare-cycle-length pox-info)))

;; get the aggregate public key for the given reward cycle (or none)
(define-read-only (get-approved-aggregate-key (reward-cycle uint))
    (map-get? aggregate-public-keys reward-cycle))

(define-private (is-in-voting-window (height uint) (reward-cycle uint))
    (let ((last-cycle (unwrap-panic (contract-call? .signers get-last-set-cycle))))
        (and (is-eq last-cycle reward-cycle)
            (is-in-prepare-phase height))))

(define-private (sum-weights (signer { signer: principal, weight: uint }) (acc uint))
    (+ acc (get weight signer)))

(define-private (get-total-weight (reward-cycle uint))
    (match (map-get? cycle-total-weight reward-cycle)
        total (ok total)
        (let ((signers (unwrap! (contract-call? .signers get-signers reward-cycle) (err ERR_FAILED_TO_RETRIEVE_SIGNERS)))
                (total (fold sum-weights signers u0)))
            (map-set cycle-total-weight reward-cycle total)
            (ok total))))

;; Signer vote for the aggregate public key of the next reward cycle
;;  The vote happens in the prepare phase of the current reward cycle but may be ran more than
;;  once resulting in different 'rounds.' Each signer vote is based on the weight of stacked
;;  stx tokens & fetched from the .signers contract. The vote is ran until the consensus 
;;  threshold of 70% for a specific aggregate public key is reached.
(define-public (vote-for-aggregate-public-key (signer-index uint) (key (buff 33)) (round uint) (reward-cycle uint))
    (let ((tally-key {reward-cycle: reward-cycle, round: round, aggregate-public-key: key})
            ;; vote by signer weight
            (signer-weight (try! (get-current-signer-weight signer-index)))
            (new-total (+ signer-weight (default-to u0 (map-get? tally tally-key))))
            (total-weight (try! (get-total-weight reward-cycle))))
        ;; Check that key isn't already set
        (asserts! (is-none (map-get? aggregate-public-keys reward-cycle)) (err ERR_OUT_OF_VOTING_WINDOW))
        ;; Check that the aggregate public key is correct length
        (asserts! (is-eq (len key) u33) (err ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY))
        ;; Check that aggregate public key has not been used before
        (asserts! (is-valid-aggregate-public-key key reward-cycle) (err ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY))
        ;; Check that signer hasn't voted in reward-cycle & round
        (asserts! (map-insert votes {reward-cycle: reward-cycle, round: round, signer: tx-sender} {aggregate-public-key: key, signer-weight: signer-weight}) (err ERR_DUPLICATE_VOTE))
        ;; Update tally aggregate public key candidate
        (map-set tally tally-key new-total)
        ;; Update used aggregate public keys
        (map-set used-aggregate-public-keys key reward-cycle)
        (update-last-round reward-cycle round)
        (print {
            event: "voted",
            signer: tx-sender,
            reward-cycle: reward-cycle,
            round: round,
            key: key,
            new-total: new-total,
        })
        ;; Check if consensus has been reached
        (and
            ;; If the new total weight is greater than or equal to the threshold consensus
            (>= (/ (* new-total u1000) total-weight) threshold-consensus)
            ;; Save this approved aggregate public key for this reward cycle.
            ;; If there is already a key for this cycle, this will return false
            ;; there will be no duplicate event.
            (map-insert aggregate-public-keys reward-cycle key)
            ;; Create an event for the approved aggregate public key
            (begin
                (print {
                    event: "approved-aggregate-public-key",
                    reward-cycle: reward-cycle,
                    key: key,
                })
                true
            )
        )

        (ok true)))

(define-private (update-last-round (reward-cycle uint) (round uint))
    (match (map-get? rounds reward-cycle)
        last-round (and (> round last-round) (map-set rounds reward-cycle round))
        (map-set rounds reward-cycle round)))
